//! The interaction service: keep a validated authorization request while its user signs in.
//!
//! A pending authorization is the request exactly as `/authorize` validated it, under a random id, so the login
//! ceremony resumes it without trusting anything the browser sends back but that id. It lives ten minutes: the store
//! expires the record, and a read judges its age by this server's clock as well, so a record the store has not yet
//! removed is never resumed late. A pushed request waits unclaimed for its minute and is claimed once, by the client
//! that pushed it, in one conditional write; until then it is not a pending sign-in.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_constants::{
    INTERACTION_CLAIM_ATTEMPTS, INTERACTION_TTL_SECS, PUSHED_REQUEST_TTL_SECS,
};
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_infrastructure::custody::token_id;
use tessari_oauth_types::{Challenge, ClientId, Resource, ScopeSet, TenantId, Timestamp};

use super::InteractionEntity;
use super::repository::InteractionRepository;
use crate::{Error, Result, Tenancy, retry};

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

/// Whether `entity` was made to `tenant` and is younger than `lifetime_secs` at `now`, by this server's clock.
fn current(
    entity: &InteractionEntity,
    tenant: &TenantId,
    lifetime_secs: u64,
    now: Timestamp,
) -> Result<bool> {
    let lifetime = i64::try_from(lifetime_secs).map_err(|_| unreadable("lifetime"))?;
    let lapses_at = entity
        .created_at
        .checked_add(lifetime)
        .ok_or_else(|| unreadable("created_at"))?;
    Ok(entity.tenant == tenant.as_str() && seconds(now)? < lapses_at)
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
        silent: entity.silent,
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
        self.keep(tenant, request, now, Some(seconds(now)?)).await
    }

    /// Keep `request`, pushed by its client to `tenant` at `now` (RFC 9126), unclaimed until the browser brings its id.
    ///
    /// # Errors
    ///
    /// When the system's random source fails, or the store is unavailable or refuses.
    pub async fn push(
        &self,
        tenant: &TenantId,
        request: &AuthorizationRequest,
        now: Timestamp,
    ) -> Result<String> {
        self.keep(tenant, request, now, None).await
    }

    /// Claim the pushed request kept as `id` in `tenant` for `client_id` at `now`, once.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or holds a row this crate cannot read.
    pub async fn claim(
        &self,
        tenant: &TenantId,
        id: &str,
        client_id: &ClientId,
        now: Timestamp,
    ) -> Result<Option<AuthorizationRequest>> {
        let place = self.tenancy.place(tenant)?;
        let at = seconds(now)?;
        let claimed = retry::bounded(INTERACTION_CLAIM_ATTEMPTS, retry::on_store_retry, || {
            self.repository.claim(&place, id, client_id.as_str(), at)
        })
        .await;
        let entity = match claimed {
            Ok(Some(entity)) => entity,
            Ok(None) => return Ok(None),
            // Only the store saying no is answered by looking again: claimed already, or another client's, is no
            // claim; anything else about that refusal stays the store's error.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                return match self.repository.find(&place, id).await? {
                    Some(row)
                        if row.claimed_at.is_none() && row.client_id == client_id.as_str() =>
                    {
                        Err(refusal)
                    }
                    _ => Ok(None),
                };
            }
            Err(failure) => return Err(failure),
        };
        // Spent either way: a pushed request that lapsed or names another tenant is claimed and refused.
        if !current(&entity, tenant, PUSHED_REQUEST_TTL_SECS, now)? {
            return Ok(None);
        }
        to_request(entity).map(Some)
    }

    /// Take the pending authorization kept as `id` in `tenant` at `now`, once, when its code is issued. A pushed one
    /// its browser never brought, a lapsed one and another tenant's are taken and not handed out.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or holds a row this crate cannot read.
    pub async fn finish(
        &self,
        tenant: &TenantId,
        id: &str,
        now: Timestamp,
    ) -> Result<Option<AuthorizationRequest>> {
        let place = self.tenancy.place(tenant)?;
        let taken = retry::take_once(
            INTERACTION_CLAIM_ATTEMPTS,
            || self.repository.take(&place, id),
            || async { Ok(self.repository.find(&place, id).await?.is_some()) },
        )
        .await?;
        let Some(entity) = taken else {
            return Ok(None);
        };
        if entity.claimed_at.is_none() || !current(&entity, tenant, INTERACTION_TTL_SECS, now)? {
            return Ok(None);
        }
        to_request(entity).map(Some)
    }

    async fn keep(
        &self,
        tenant: &TenantId,
        request: &AuthorizationRequest,
        now: Timestamp,
        claimed_at: Option<i64>,
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
            silent: request.silent,
            created_at: seconds(now)?,
            claimed_at,
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
        // A pushed request is not a pending sign-in until its browser has brought it.
        if entity.claimed_at.is_none() || !current(&entity, tenant, INTERACTION_TTL_SECS, now)? {
            return Ok(None);
        }
        to_request(entity).map(Some)
    }
}
