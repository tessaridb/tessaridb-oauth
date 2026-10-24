//! A client registered in a company's console by an operator holding `clients`, through the same registration the
//! rest of the server uses. The request names exactly the fields a registration has and no others (no company: the
//! operator's session decides it), and every value is read by the type the server keeps it as. Only the two ways
//! this server verifies at its token endpoint are offered: `none` for a public client, which always uses PKCE, and
//! `private_key_jwt` for a confidential one; no shared secret is ever made. The server's own console client is
//! reserved. Removing a client ends with it every user's grant to it and every refresh family it held; the access
//! tokens already issued to it stop working when they expire, which the answer states.

use std::collections::BTreeSet;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use tessari_oauth_constants::{ACCESS_TOKEN_TTL_SECS, ADMIN_CONSOLE_CLIENT};
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{
    Algorithm, ClientId, ErrorCategory, RedirectUri, Resource, ScopeSet, Sector,
};

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::clients_read::shown;
use crate::{Error, Result};

/// The change `POST .../api/clients` names.
const REGISTER: &str = "clients.register";
/// The change `POST .../api/clients/{client}/remove` names.
const REMOVE: &str = "clients.remove";

/// A client to register, as the console sends it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Registering {
    client_id: String,
    redirect_uris: Vec<String>,
    scope_ceiling: Vec<String>,
    #[serde(default)]
    resources: Vec<String>,
    auth_method: String,
    assertion_alg: Option<String>,
    #[serde(default)]
    jwks: Vec<Box<RawValue>>,
    grant_types: Vec<String>,
    #[serde(default)]
    dpop_bound_access_tokens: bool,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    backchannel_logout_uri: Option<String>,
    sector: Option<String>,
    reason: String,
}

impl Reasoned for Registering {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// A removal: why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Removal {
    reason: String,
}

impl Reasoned for Removal {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// A client removed: which, how many users' grants and refresh families ended with it, and when the access tokens
/// already issued to it stop working.
#[derive(Serialize)]
struct Removed<'a> {
    client_id: &'a str,
    consents: usize,
    families: usize,
    access_tokens_end_by: u64,
}

/// The one way `sent` authenticates at the token endpoint: `none`, or `private_key_jwt` under the algorithm it names.
fn auth_method(sent: &Registering) -> Result<AuthMethod> {
    match (sent.auth_method.as_str(), sent.assertion_alg.as_deref()) {
        ("none", None) => Ok(AuthMethod::None),
        ("private_key_jwt", Some(name)) => Algorithm::ALL
            .into_iter()
            .find(|algorithm| algorithm.name() == name)
            .map(AuthMethod::PrivateKeyJwt)
            .ok_or(Error::Invalid),
        _ => Err(Error::Invalid),
    }
}

/// The registration `sent` describes, every value read by its own type, or refused.
fn registration(sent: Registering) -> Result<NewClient> {
    let auth_method = auth_method(&sent)?;
    let uris = |raw: Vec<String>| {
        raw.into_iter()
            .map(|uri| RedirectUri::parse(uri).map_err(|_| Error::Invalid))
            .collect::<Result<Vec<_>>>()
    };
    let grant_types = sent
        .grant_types
        .iter()
        .map(|name| {
            GrantType::ALL
                .into_iter()
                .find(|grant| grant.name() == name)
                .ok_or(Error::Invalid)
        })
        .collect::<Result<Vec<_>>>()?;
    let redirect_uris = uris(sent.redirect_uris)?;
    // A client with no grant is nothing, and a code flow with no redirect URI has nowhere to send its code.
    if grant_types.is_empty()
        || (grant_types.contains(&GrantType::AuthorizationCode) && redirect_uris.is_empty())
    {
        return Err(Error::Invalid);
    }
    // A JWK is kept as the JSON text it was registered as, which the registration then checks is a public key; it
    // is read here only far enough to know it is an object.
    let jwks = sent
        .jwks
        .iter()
        .map(|jwk| {
            let text = jwk.get();
            if text.starts_with('{') {
                Ok(text.to_owned())
            } else {
                Err(Error::Invalid)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(NewClient {
        client_id: ClientId::parse(sent.client_id).map_err(|_| Error::Invalid)?,
        redirect_uris,
        scope_ceiling: ScopeSet::parse(&sent.scope_ceiling.join(" "))
            .map_err(|_| Error::Invalid)?,
        resources: sent
            .resources
            .into_iter()
            .map(|resource| Resource::parse(resource).map_err(|_| Error::Invalid))
            .collect::<Result<BTreeSet<_>>>()?,
        auth_method,
        grant_types,
        jwks,
        dpop_bound_access_tokens: sent.dpop_bound_access_tokens,
        post_logout_redirect_uris: uris(sent.post_logout_redirect_uris)?,
        backchannel_logout_uri: sent
            .backchannel_logout_uri
            .map(|uri| RedirectUri::parse(uri).map_err(|_| Error::Invalid))
            .transpose()?,
        sector: sent
            .sector
            .map(|sector| Sector::parse(sector).map_err(|_| Error::Invalid))
            .transpose()?,
    })
}

/// A refusal kept as the change's answer.
fn refused(status: StatusCode, code: &'static str, message: &'static str) -> Result<Made> {
    Ok(Made {
        status,
        body: serde_json::to_string(&Refusal { code, message }).map_err(|_| Error::Internal)?,
        shown: None,
        user: None,
    })
}

/// Register the client the request describes in `company`.
pub(super) async fn register(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let clients = std::sync::Arc::clone(&state.clients);
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Clients, REGISTER),
        |operator, sent: Registering| async move {
            let client = registration(sent)?;
            if client.client_id.as_str() == ADMIN_CONSOLE_CLIENT {
                return refused(
                    StatusCode::CONFLICT,
                    "client_reserved",
                    "this id belongs to the console's own client",
                );
            }
            match clients.register(&operator.tenant, &client, now).await {
                Ok(registered) => Ok(Made {
                    status: StatusCode::CREATED,
                    body: serde_json::to_string(&shown(&registered))
                        .map_err(|_| Error::Internal)?,
                    shown: None,
                    user: None,
                }),
                Err(failure) if failure.category() == ErrorCategory::Conflict => refused(
                    StatusCode::CONFLICT,
                    "client_taken",
                    "this company already has a client with this id",
                ),
                Err(failure) if failure.category() == ErrorCategory::Validation => {
                    Err(Error::Invalid)
                }
                Err(failure) => Err(Error::Store(failure)),
            }
        },
    )
    .await
}

/// Remove the client `client` of `company` and end every grant and refresh family it held. A removal whose cascade
/// did not finish is completed by sending it again; one that finds nothing left to end answers that there is no such
/// client.
pub(super) async fn remove(
    State(state): State<AdminState>,
    Path((company, client)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let removals = std::sync::Arc::clone(&state.client_removals);
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Clients, REMOVE),
        |operator, _: Removal| async move {
            let Ok(client) = ClientId::parse(client) else {
                return missing();
            };
            if client.as_str() == ADMIN_CONSOLE_CLIENT {
                return refused(
                    StatusCode::CONFLICT,
                    "client_reserved",
                    "the console's own client is not removed",
                );
            }
            let removed = removals
                .remove(&operator.tenant, &client, now)
                .await
                .map_err(Error::Store)?;
            if !removed.registered && removed.consents == 0 && removed.families == 0 {
                return missing();
            }
            let access_tokens_end_by = now
                .unix_secs()
                .checked_add(ACCESS_TOKEN_TTL_SECS)
                .ok_or(Error::Internal)?;
            Ok(Made {
                status: StatusCode::OK,
                body: serde_json::to_string(&Removed {
                    client_id: client.as_str(),
                    consents: removed.consents,
                    families: removed.families,
                    access_tokens_end_by,
                })
                .map_err(|_| Error::Internal)?,
                shown: None,
                user: None,
            })
        },
    )
    .await
}

/// The answer for a client the company has not registered, kept as the change's answer.
fn missing() -> Result<Made> {
    refused(
        StatusCode::NOT_FOUND,
        "client_not_found",
        "this company has no such client",
    )
}
