//! The interaction service: keep a validated authorization request while its user signs in.
//!
//! A pending authorization is the request exactly as `/authorize` validated it, under a random id, so the login
//! ceremony resumes it without trusting anything the browser sends back but that id. It lives ten minutes: the store
//! expires the record, and a read judges its age by this server's clock as well, so a record the store has not yet
//! removed is never resumed late.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_constants::INTERACTION_TTL_SECS;
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_infrastructure::custody::token_id;
use tessari_oauth_types::{Challenge, ClientId, Resource, ScopeSet, TenantId, Timestamp};

use super::InteractionEntity;
use super::repository::InteractionRepository;
use crate::{Error, Result, Tenancy};

/// Pending authorizations.
#[derive(Clone)]
pub struct InteractionService {
    repository: Arc<dyn InteractionRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "interaction",
        reason: reason.to_owned(),
    }
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| unreadable("time beyond i64"))
}

fn to_request(entity: InteractionEntity) -> Result<AuthorizationRequest> {
    Ok(AuthorizationRequest {
        client_id: ClientId::parse(entity.client_id).map_err(|_| unreadable("client_id"))?,
        redirect_uri: entity.redirect_uri,
        scopes: ScopeSet::parse(&entity.scopes.join(" ")).map_err(|_| unreadable("scopes"))?,
        challenge: Challenge::parse(entity.challenge).map_err(|_| unreadable("challenge"))?,
        state: entity.state,
        resources: entity
            .resources
            .into_iter()
            .map(|resource| Resource::parse(resource).map_err(|_| unreadable("resources")))
            .collect::<Result<BTreeSet<Resource>>>()?,
        nonce: entity.nonce,
    })
}

impl InteractionService {
    pub(crate) fn new(repository: Arc<dyn InteractionRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Keep `request`, made to `tenant` at `now`, and answer the id the login ceremony resumes it by.
    ///
    /// # Errors
    ///
    /// When the system's random source fails, or the store is unavailable or refuses.
    pub async fn open(
        &self,
        tenant: &TenantId,
        request: &AuthorizationRequest,
        now: Timestamp,
    ) -> Result<String> {
        let place = self.tenancy.place(tenant)?;
        let id = token_id()?;
        let entity = InteractionEntity {
            tenant: tenant.as_str().to_owned(),
            client_id: request.client_id.as_str().to_owned(),
            redirect_uri: request.redirect_uri.clone(),
            scopes: request.scopes.iter().map(str::to_owned).collect(),
            challenge: request.challenge.as_str().to_owned(),
            state: request.state.clone(),
            resources: request
                .resources
                .iter()
                .map(|resource| resource.as_str().to_owned())
                .collect(),
            nonce: request.nonce.clone(),
            created_at: seconds(now)?,
        };
        self.repository.create(&place, &id, &entity).await?;
        Ok(id)
    }

    /// The request kept as `id` in `tenant`, unless there is none or it is older than its lifetime at `now`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or holds a row this crate cannot read.
    pub async fn find(
        &self,
        tenant: &TenantId,
        id: &str,
        now: Timestamp,
    ) -> Result<Option<AuthorizationRequest>> {
        let place = self.tenancy.place(tenant)?;
        let Some(entity) = self.repository.find(&place, id).await? else {
            return Ok(None);
        };
        let lifetime = i64::try_from(INTERACTION_TTL_SECS).map_err(|_| unreadable("lifetime"))?;
        let lapses_at = entity
            .created_at
            .checked_add(lifetime)
            .ok_or_else(|| unreadable("created_at"))?;
        if entity.tenant != tenant.as_str() || seconds(now)? >= lapses_at {
            return Ok(None);
        }
        to_request(entity).map(Some)
    }
}
