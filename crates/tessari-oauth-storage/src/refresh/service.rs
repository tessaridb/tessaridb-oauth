//! The refresh service: start a family, rotate a token once, and revoke the whole family when a spent token comes
//! back.
//!
//! Rotation without reuse detection is not rotation. A spent token presented again means two parties hold the
//! chain — the thief and the victim diverged at the moment of theft, and which chain is whose cannot be known — so
//! the family is revoked whole. The spend and the successor land in one transaction, so a successor exists exactly
//! when its predecessor was spent. A token that does not rotate for any other reason (unknown, expired, a revoked
//! family, another client) changes nothing.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_constants::{
    REFRESH_ABSOLUTE_TTL_SECS, REFRESH_IDLE_TTL_SECS, REFRESH_ROTATE_ATTEMPTS,
};
use tessari_oauth_infrastructure::tessaridb::Place;
use tessari_oauth_types::{
    ClientId, RefreshToken, Resource, ScopeSet, TenantId, Timestamp, UserId,
};

use super::repository::RefreshRepository;
use super::{FamilyEntity, RefreshGrant, Rotation, RotationRefusal, TokenEntity};
use crate::{Error, Result, Tenancy, retry};

/// Why a family was revoked when the reuse of one of its tokens ended it.
const REUSE: &str = "reuse";

/// Refresh-token families.
#[derive(Clone)]
pub struct RefreshService {
    repository: Arc<dyn RefreshRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "refresh token",
        reason: reason.to_owned(),
    }
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| unreadable("time beyond i64"))
}

fn later(at: i64, by: u64) -> Result<i64> {
    i64::try_from(by)
        .ok()
        .and_then(|by| at.checked_add(by))
        .ok_or_else(|| unreadable("expiry beyond i64"))
}

fn to_grant(token: &TokenEntity) -> Result<RefreshGrant> {
    let resources = token
        .resources
        .iter()
        .map(|resource| Resource::parse(resource.clone()).map_err(|_| unreadable("resources")))
        .collect::<Result<BTreeSet<Resource>>>()?;
    Ok(RefreshGrant {
        tenant: TenantId::parse(token.tenant.clone()).map_err(|_| unreadable("tenant"))?,
        user: UserId::parse(token.user_id.clone()).map_err(|_| unreadable("user_id"))?,
        client_id: ClientId::parse(token.client_id.clone()).map_err(|_| unreadable("client_id"))?,
        scopes: ScopeSet::parse(&token.scopes.join(" ")).map_err(|_| unreadable("scopes"))?,
        resources,
    })
}

impl RefreshService {
    pub(crate) fn new(repository: Arc<dyn RefreshRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Start a family whose first token is `first`, carrying `grant`, at `now`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses — including a token that already exists at that digest.
    pub async fn start(
        &self,
        first: &RefreshToken,
        grant: &RefreshGrant,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(&grant.tenant)?;
        let at = seconds(now)?;
        let family_id = first.digest();
        let family = FamilyEntity {
            tenant: grant.tenant.as_str().to_owned(),
            client_id: grant.client_id.as_str().to_owned(),
            user_id: grant.user.as_str().to_owned(),
            created_at: at,
            expires_at: later(at, REFRESH_ABSOLUTE_TTL_SECS)?,
            revoked_at: None,
            revoked_reason: None,
        };
        let token = TokenEntity {
            family_id: family_id.clone(),
            tenant: family.tenant.clone(),
            client_id: family.client_id.clone(),
            user_id: family.user_id.clone(),
            scopes: grant.scopes.iter().map(str::to_owned).collect(),
            resources: grant
                .resources
                .iter()
                .map(|resource| resource.as_str().to_owned())
                .collect(),
            idle_expires_at: later(at, REFRESH_IDLE_TTL_SECS)?.min(family.expires_at),
            rotated_at: None,
        };
        self.repository
            .start(&place, &family_id, &family, &family_id, &token)
            .await
    }

    /// Present `presented` from `client` at `now`, rotating it to `next` when it may rotate.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses for a reason other than the token having been spent, or holds a row
    /// this crate cannot read.
    pub async fn rotate(
        &self,
        tenant: &TenantId,
        presented: &RefreshToken,
        next: &RefreshToken,
        client: &ClientId,
        now: Timestamp,
    ) -> Result<Rotation> {
        let place = self.tenancy.place(tenant)?;
        let spent = presented.digest();
        let at = seconds(now)?;
        let Some(token) = self.repository.find_token(&place, &spent).await? else {
            return Ok(Rotation::Refused(RotationRefusal::Unknown));
        };
        let Some(family) = self
            .repository
            .find_family(&place, &token.family_id)
            .await?
        else {
            return Ok(Rotation::Refused(RotationRefusal::Unknown));
        };
        if family.revoked_at.is_some() {
            return Ok(Rotation::Refused(RotationRefusal::FamilyRevoked));
        }
        if token.client_id != client.as_str() {
            return Ok(Rotation::Refused(RotationRefusal::OtherClient));
        }
        if token.rotated_at.is_some() {
            return self.reused(&place, &token, at).await;
        }
        // Every token's idle bound is capped at its family's absolute one, so this one comparison holds both.
        if at >= token.idle_expires_at {
            return Ok(Rotation::Refused(RotationRefusal::Expired));
        }
        let successor = TokenEntity {
            idle_expires_at: later(at, REFRESH_IDLE_TTL_SECS)?.min(family.expires_at),
            rotated_at: None,
            ..token.clone()
        };
        let next_id = next.digest();
        let outcome = retry::bounded(REFRESH_ROTATE_ATTEMPTS, retry::on_store_retry, || {
            self.repository
                .rotate(&place, &spent, at, &next_id, &successor)
        })
        .await;
        match outcome {
            Ok(()) => Ok(Rotation::Rotated(to_grant(&token)?)),
            // The store said no: if the token is now spent, somebody else rotated it first — a reuse.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                match self.repository.find_token(&place, &spent).await? {
                    Some(now_spent) if now_spent.rotated_at.is_some() => {
                        self.reused(&place, &token, at).await
                    }
                    _ => Err(refusal),
                }
            }
            Err(failure) => Err(failure),
        }
    }

    /// End `token`'s family because a spent token came back, and answer the reuse.
    async fn reused(&self, place: &Place, token: &TokenEntity, at: i64) -> Result<Rotation> {
        self.end_family(place, &token.family_id, at, REUSE).await?;
        Ok(Rotation::Reused(to_grant(token)?))
    }

    /// Revoke the family `family_id` in `tenant` for `reason`; a family already revoked stays as it was.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses for a reason other than the family being revoked already.
    pub async fn revoke(
        &self,
        tenant: &TenantId,
        family_id: &str,
        reason: &str,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.end_family(&place, family_id, seconds(now)?, reason)
            .await
    }

    async fn end_family(
        &self,
        place: &Place,
        family_id: &str,
        at: i64,
        reason: &str,
    ) -> Result<()> {
        let outcome = retry::bounded(REFRESH_ROTATE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.revoke_family(place, family_id, at, reason)
        })
        .await;
        match outcome {
            Ok(()) => Ok(()),
            // Refused: either the family is revoked already — the outcome wanted — or something else.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                match self.repository.find_family(place, family_id).await? {
                    Some(family) if family.revoked_at.is_some() => Ok(()),
                    _ => Err(refusal),
                }
            }
            Err(failure) => Err(failure),
        }
    }
}
