//! The factor service: a user's one-time code secret, the last time step it accepted, and their recovery codes.
//!
//! The secret is sealed under the key-encryption key for this tenant and this user, so a row copied to another user or
//! another tenant does not open. A time step is accepted by ONE conditional write — move the last step forward only
//! while it is below this one — so two requests carrying the same code cannot both pass; the loser is told what
//! happened by reading the factor again, never by the refusal's wording. A recovery code is spent by one delete of the
//! record its owner and digest name, so of two spends of one code only one finds it.

use std::sync::Arc;

use zeroize::Zeroizing;

use tessari_oauth_constants::FACTOR_WRITE_ATTEMPTS;
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_types::{ErrorCategory, TenantId, Timestamp, UserId, base64url};

use super::entity::PendingTotpEntity;
use super::repository::FactorRepository;
use super::{Enrolled, FactorSummary, TotpEntity, TotpFactor};
use crate::{Error, Result, Tenancy, retry};

/// Second factors.
#[derive(Clone)]
pub struct FactorService {
    repository: Arc<dyn FactorRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "factor",
        reason: reason.to_owned(),
    }
}

const fn invalid(reason: &'static str) -> Error {
    Error::Invalid {
        record: "factor",
        reason,
    }
}

/// What the secret is sealed for: one user's one-time code factor.
fn binding(user: &UserId) -> String {
    format!("totp:{}", user.as_str())
}

/// What a secret being enrolled is sealed for, apart from an enrolled one, so neither opens as the other.
fn pending_binding(user: &UserId) -> String {
    format!("totp-pending:{}", user.as_str())
}

fn unix_secs(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| invalid("time beyond i64"))
}

impl FactorService {
    pub(crate) fn new(repository: Arc<dyn FactorRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Store `secret` as `user`'s one-time code factor in `tenant`, sealed under `kek`, at `now`.
    ///
    /// # Errors
    ///
    /// Custody and store failures.
    pub async fn enroll_totp(
        &self,
        tenant: &TenantId,
        kek: &Kek,
        user: &UserId,
        secret: &[u8],
        now: Timestamp,
    ) -> Result<Enrolled> {
        let place = self.tenancy.place(tenant)?;
        let factor = TotpEntity {
            user_id: user.as_str().to_owned(),
            sealed: base64url::encode(&kek.seal(tenant, &binding(user), secret)?),
            last_step: 0,
            created_at: unix_secs(now)?,
        };
        let created = retry::bounded(FACTOR_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.create_totp(&place, &factor)
        })
        .await;
        match created {
            Ok(()) => Ok(Enrolled::Created),
            // Replacing a factor is a re-enrolment ceremony, so the one already there stays.
            Err(Error::Store(store))
                if store.category() == ErrorCategory::Conflict && !store.is_retry() =>
            {
                Ok(Enrolled::AlreadyEnrolled)
            }
            Err(failure) => Err(failure),
        }
    }

    /// Remove `user`'s authenticator app in `tenant` together with every unspent recovery code, which only ever
    /// stood in for the app's code; whether there was an app to remove.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn remove_totp(&self, tenant: &TenantId, user: &UserId) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        if self
            .repository
            .find_totp(&place, user.as_str())
            .await?
            .is_none()
        {
            return Ok(false);
        }
        // Two removals racing both find the app and both delete; the second deletes nothing, which is the same end.
        self.repository.remove_totp(&place, user.as_str()).await?;
        Ok(true)
    }

    /// `user`'s one-time code factor in `tenant`, opened under `kek`, when there is one.
    ///
    /// # Errors
    ///
    /// A custody failure when the secret does not open under `kek` for this tenant and user; store failures.
    pub async fn totp(
        &self,
        tenant: &TenantId,
        kek: &Kek,
        user: &UserId,
    ) -> Result<Option<TotpFactor>> {
        let place = self.tenancy.place(tenant)?;
        let Some(kept) = self.repository.find_totp(&place, user.as_str()).await? else {
            return Ok(None);
        };
        let sealed = base64url::decode(&kept.sealed).map_err(|_| unreadable("sealed"))?;
        Ok(Some(TotpFactor {
            secret: kek.unseal(tenant, &binding(user), &sealed)?,
            last_step: u64::try_from(kept.last_step).map_err(|_| unreadable("negative step"))?,
        }))
    }

    /// Record `step` as the last one accepted for `user`; `false` when that step or a later one already was.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] when the user has no factor.
    pub async fn accept_step(&self, tenant: &TenantId, user: &UserId, step: u64) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let step = i64::try_from(step).map_err(|_| invalid("step beyond i64"))?;
        let advanced = retry::bounded(FACTOR_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.advance_step(&place, user.as_str(), step)
        })
        .await;
        match advanced {
            Ok(()) => Ok(true),
            // Only the store saying no is answered by looking again; the factor's step says why it said no.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                match self.repository.find_totp(&place, user.as_str()).await? {
                    None => Err(invalid("no factor enrolled")),
                    Some(kept) if kept.last_step >= step => Ok(false),
                    Some(_) => Err(refusal),
                }
            }
            Err(failure) => Err(failure),
        }
    }

    /// Replace `user`'s recovery codes with those `digests` name, at `now`.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn issue_recovery_codes(
        &self,
        tenant: &TenantId,
        user: &UserId,
        digests: &[String],
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let at = unix_secs(now)?;
        // Delete-all then create in one transaction, so asking again after a `retry` lands the same set.
        retry::bounded(FACTOR_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository
                .replace_codes(&place, user.as_str(), digests, at)
        })
        .await
    }

    /// Spend `user`'s recovery code under `digest`; `false` when there is none of theirs to spend.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn spend_recovery_code(
        &self,
        tenant: &TenantId,
        user: &UserId,
        digest: &str,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let spent = retry::bounded(FACTOR_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.delete_code(&place, user.as_str(), digest)
        })
        .await;
        match spent {
            // A delete that keeps meeting other requests' deletes of the same code: when the code is gone, one of
            // them spent it.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                if self
                    .repository
                    .has_code(&place, user.as_str(), digest)
                    .await?
                {
                    Err(refusal)
                } else {
                    Ok(false)
                }
            }
            other => other,
        }
    }

    /// Which second factors `user` of `tenant` holds, without opening any of them.
    ///
    /// # Errors
    ///
    /// The store's failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn summary(&self, tenant: &TenantId, user: &UserId) -> Result<FactorSummary> {
        let place = self.tenancy.place(tenant)?;
        let totp = self
            .repository
            .find_totp(&place, user.as_str())
            .await?
            .is_some();
        let recovery_codes = self.repository.count_codes(&place, user.as_str()).await?;
        Ok(FactorSummary {
            totp,
            recovery_codes,
        })
    }

    /// Keep `secret` for `user` in `tenant` as the one-time code factor the session `sid` is enrolling, sealed under
    /// `kek`, until it is confirmed or ten minutes pass; a later call for the same session replaces it.
    ///
    /// # Errors
    ///
    /// Custody and store failures.
    pub async fn begin_totp(
        &self,
        tenant: &TenantId,
        kek: &Kek,
        user: &UserId,
        sid: &str,
        secret: &[u8],
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let pending = PendingTotpEntity {
            user_id: user.as_str().to_owned(),
            sealed: base64url::encode(&kek.seal(tenant, &pending_binding(user), secret)?),
            created_at: unix_secs(now)?,
        };
        self.repository.put_pending(&place, sid, &pending).await
    }

    /// Take, once, the secret the session `sid` of `user` in `tenant` is enrolling, opened under `kek`; `None` when
    /// there is none, it lapsed, or it is not `user`'s.
    ///
    /// # Errors
    ///
    /// A custody failure when it does not open; store failures.
    pub async fn take_pending_totp(
        &self,
        tenant: &TenantId,
        kek: &Kek,
        user: &UserId,
        sid: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let place = self.tenancy.place(tenant)?;
        // A session's public id names one user's session, so the owner read here is the one whose secret is taken.
        let owned = self
            .repository
            .find_pending(&place, sid)
            .await?
            .is_some_and(|pending| pending.user_id == user.as_str());
        if !owned {
            return Ok(None);
        }
        let Some(taken) = self.repository.take_pending(&place, sid).await? else {
            return Ok(None);
        };
        let sealed = base64url::decode(&taken.sealed).map_err(|_| unreadable("sealed"))?;
        Ok(Some(kek.unseal(tenant, &pending_binding(user), &sealed)?))
    }
}
