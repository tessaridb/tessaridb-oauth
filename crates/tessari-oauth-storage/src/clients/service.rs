//! The client service: register a client once, and find a registration in its own tenant.
//!
//! A registration is checked before it is written — every key a public signing key under the client's algorithm,
//! keys present exactly when the client authenticates with them — so what `find` reads back is what was accepted.
//! A stored row that no longer reads as a registration is an error, never a client, so the request fails closed.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_core::clients::{AuthMethod, ClientRegistration, GrantType};
use tessari_oauth_core::jose::VerifyingKey;
use tessari_oauth_types::{
    Algorithm, ClientId, RedirectUri, Resource, ScopeSet, TenantId, Timestamp,
};

use super::repository::ClientRepository;
use super::{ClientEntity, NewClient};
use crate::{Error, Result, Tenancy};

/// Client registrations.
#[derive(Clone)]
pub struct ClientService {
    repository: Arc<dyn ClientRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: impl Into<String>) -> Error {
    Error::Unreadable {
        record: "client",
        reason: reason.into(),
    }
}

const fn method_name(method: AuthMethod) -> (&'static str, Option<&'static str>) {
    match method {
        AuthMethod::PrivateKeyJwt(algorithm) => (method.name(), Some(algorithm.name())),
        _ => (method.name(), None),
    }
}

fn method_from(name: &str, algorithm: Option<&str>) -> Option<AuthMethod> {
    let algorithm = algorithm.map(|name| {
        Algorithm::ALL
            .into_iter()
            .find(|known| known.name() == name)
    });
    match (name, algorithm) {
        ("none", None) => Some(AuthMethod::None),
        ("client_secret_basic", None) => Some(AuthMethod::ClientSecretBasic),
        ("client_secret_post", None) => Some(AuthMethod::ClientSecretPost),
        ("private_key_jwt", Some(Some(algorithm))) => Some(AuthMethod::PrivateKeyJwt(algorithm)),
        _ => None,
    }
}

/// The client's keys parsed under its method: some exactly when it authenticates with an assertion.
fn keys(method: AuthMethod, jwks: &[String]) -> Option<Vec<VerifyingKey>> {
    match method {
        AuthMethod::PrivateKeyJwt(algorithm) if !jwks.is_empty() => jwks
            .iter()
            .map(|jwk| VerifyingKey::from_jwk(jwk, algorithm).ok())
            .collect(),
        AuthMethod::PrivateKeyJwt(_) => None,
        _ if jwks.is_empty() => Some(Vec::new()),
        _ => None,
    }
}

/// The registration `entity` records in `tenant`.
fn registration(tenant: &TenantId, entity: ClientEntity) -> Result<ClientRegistration> {
    let auth_method = method_from(&entity.auth_method, entity.assertion_alg.as_deref())
        .ok_or_else(|| unreadable("an authentication method this server does not know"))?;
    let grant_types = entity
        .grant_types
        .iter()
        .map(|name| {
            GrantType::ALL
                .into_iter()
                .find(|grant| grant.name() == name)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| unreadable("a grant type this server does not know"))?;
    let redirect_uris = entity
        .redirect_uris
        .into_iter()
        .map(RedirectUri::parse)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|fault| unreadable(fault.to_string()))?;
    let post_logout_redirect_uris = entity
        .post_logout_redirect_uris
        .unwrap_or_default()
        .into_iter()
        .map(RedirectUri::parse)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|fault| unreadable(fault.to_string()))?;
    Ok(ClientRegistration {
        tenant: tenant.clone(),
        client_id: ClientId::parse(entity.client_id)
            .map_err(|fault| unreadable(fault.to_string()))?,
        redirect_uris,
        scope_ceiling: ScopeSet::parse(&entity.scope_ceiling.join(" "))
            .map_err(|fault| unreadable(fault.to_string()))?,
        resources: entity
            .resources
            .into_iter()
            .map(Resource::parse)
            .collect::<std::result::Result<BTreeSet<_>, _>>()
            .map_err(|fault| unreadable(fault.to_string()))?,
        auth_method,
        grant_types,
        keys: keys(auth_method, &entity.jwks)
            .ok_or_else(|| unreadable("a key that does not parse"))?,
        dpop_bound_access_tokens: entity.dpop_bound_access_tokens,
        post_logout_redirect_uris,
    })
}

impl ClientService {
    pub(crate) fn new(repository: Arc<dyn ClientRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Register `client` in `tenant` at `now`, answering the registration as `find` will read it.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when a key is not a public signing key under the client's algorithm, or keys are missing for
    /// `private_key_jwt` or given for another method; a conflict when the id is already registered; and the store's
    /// failures.
    pub async fn register(
        &self,
        tenant: &TenantId,
        client: &NewClient,
        now: Timestamp,
    ) -> Result<ClientRegistration> {
        keys(client.auth_method, &client.jwks).ok_or(Error::Invalid {
            record: "client",
            reason: "keys must be public signing keys, given exactly for private_key_jwt",
        })?;
        // A public client's credentials are in every copy of it, so they cannot stand for a client acting as itself.
        if client.auth_method == AuthMethod::None
            && client.grant_types.contains(&GrantType::ClientCredentials)
        {
            return Err(Error::Invalid {
                record: "client",
                reason: "client_credentials is for confidential clients only",
            });
        }
        let (auth_method, assertion_alg) = method_name(client.auth_method);
        let entity = ClientEntity {
            tenant: tenant.as_str().to_owned(),
            client_id: client.client_id.as_str().to_owned(),
            redirect_uris: client
                .redirect_uris
                .iter()
                .map(|uri| uri.as_str().to_owned())
                .collect(),
            scope_ceiling: client.scope_ceiling.iter().map(str::to_owned).collect(),
            resources: client
                .resources
                .iter()
                .map(|resource| resource.as_str().to_owned())
                .collect(),
            auth_method: auth_method.to_owned(),
            assertion_alg: assertion_alg.map(str::to_owned),
            grant_types: client
                .grant_types
                .iter()
                .map(|grant| grant.name().to_owned())
                .collect(),
            jwks: client.jwks.clone(),
            dpop_bound_access_tokens: client.dpop_bound_access_tokens,
            registered_at: i64::try_from(now.unix_secs())
                .map_err(|_| unreadable("a time beyond i64"))?,
            post_logout_redirect_uris: Some(
                client
                    .post_logout_redirect_uris
                    .iter()
                    .map(|uri| uri.as_str().to_owned())
                    .collect(),
            ),
        };
        let place = self.tenancy.place(tenant)?;
        self.repository.create(&place, &entity).await?;
        registration(tenant, entity)
    }

    /// The registration of `client_id` in `tenant`, when there is one.
    ///
    /// # Errors
    ///
    /// When the store fails, or the stored row does not read as a registration.
    pub async fn find(
        &self,
        tenant: &TenantId,
        client_id: &ClientId,
    ) -> Result<Option<ClientRegistration>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .find(&place, client_id.as_str())
            .await?
            .map(|entity| registration(tenant, entity))
            .transpose()
    }
}
