//! The passkey service: a user's credentials with their public keys and counters, and the challenges a registration or
//! a sign-in is answered against.
//!
//! A credential is stored under its own id, so the first registration of an id owns it and a second — by anyone — is
//! told it is taken. The counter is advanced by ONE conditional write — move it forward only while it is below — so a
//! report that does not move it forward is answered `false` by reading the credential again, never by the refusal's
//! wording. A challenge is spent by one delete of its record and is good only for the ceremony it was issued for and
//! within its lifetime by this server's clock, so it answers one response at most.

use std::sync::Arc;

use tessari_oauth_constants::{PASSKEY_WRITE_ATTEMPTS, WEBAUTHN_CHALLENGE_TTL_SECS};
use tessari_oauth_core::webauthn::Registered;
use tessari_oauth_types::{ErrorCategory, TenantId, Timestamp, UserId, base64url};

use super::repository::PasskeyRepository;
use super::{
    Ceremony, ChallengeEntity, Challenged, ListedPasskey, Passkey, PasskeyEntity, Registration,
};
use crate::{Error, Result, Tenancy, answers, retry};

/// Passkeys and their challenges.
#[derive(Clone)]
pub struct PasskeyService {
    repository: Arc<dyn PasskeyRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "passkey",
        reason: reason.to_owned(),
    }
}

const fn invalid(reason: &'static str) -> Error {
    Error::Invalid {
        record: "passkey",
        reason,
    }
}

fn unix_secs(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| invalid("time beyond i64"))
}

impl PasskeyService {
    pub(crate) fn new(repository: Arc<dyn PasskeyRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Store the credential `registered` for `user` in `tenant` at `now`.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn register(
        &self,
        tenant: &TenantId,
        user: &UserId,
        registered: &Registered,
        now: Timestamp,
    ) -> Result<Registration> {
        let place = self.tenancy.place(tenant)?;
        let id = base64url::encode(&registered.credential_id);
        let passkey = PasskeyEntity {
            user_id: user.as_str().to_owned(),
            public_key: base64url::encode(&registered.public_key),
            sign_count: i64::from(registered.sign_count),
            backup_eligible: registered.backup_eligible,
            created_at: unix_secs(now)?,
        };
        let created = retry::bounded(PASSKEY_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.create_passkey(&place, &id, &passkey)
        })
        .await;
        match created {
            Ok(()) => Ok(Registration::Created),
            // A credential id already stored keeps its owner; the second registration is told so.
            Err(Error::Store(store))
                if store.category() == ErrorCategory::Conflict && !store.is_retry() =>
            {
                Ok(Registration::AlreadyRegistered)
            }
            Err(failure) => Err(failure),
        }
    }

    /// The credential `credential_id` names in `tenant`, when there is one.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn passkey(
        &self,
        tenant: &TenantId,
        credential_id: &[u8],
    ) -> Result<Option<Passkey>> {
        let place = self.tenancy.place(tenant)?;
        let id = base64url::encode(credential_id);
        let Some(kept) = self.repository.find_passkey(&place, &id).await? else {
            return Ok(None);
        };
        Ok(Some(Passkey {
            user: UserId::parse(kept.user_id).map_err(|_| unreadable("user_id"))?,
            public_key: base64url::decode(&kept.public_key)
                .map_err(|_| unreadable("public_key"))?,
            sign_count: u32::try_from(kept.sign_count).map_err(|_| unreadable("sign_count"))?,
            backup_eligible: kept.backup_eligible,
        }))
    }

    /// Record `count` as the counter of `credential_id`; `false` when the stored counter is already at or above it.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] when there is no such credential.
    pub async fn advance_count(
        &self,
        tenant: &TenantId,
        credential_id: &[u8],
        count: u32,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let id = base64url::encode(credential_id);
        let count = i64::from(count);
        let advanced = retry::bounded(PASSKEY_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.advance_count(&place, &id, count)
        })
        .await;
        match advanced {
            Ok(()) => Ok(true),
            // Only the store saying no is answered by looking again; the stored counter says why it said no.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                match self.repository.find_passkey(&place, &id).await? {
                    None => Err(invalid("no such passkey")),
                    Some(kept) if kept.sign_count >= count => Ok(false),
                    Some(_) => Err(refusal),
                }
            }
            Err(failure) => Err(failure),
        }
    }

    /// Keep `challenge` for one `ceremony`, issued at `now` to `user` when the ceremony names one.
    ///
    /// # Errors
    ///
    /// Store failures, including a refusal when the same challenge is already kept.
    pub async fn issue_challenge(
        &self,
        tenant: &TenantId,
        challenge: &[u8],
        ceremony: Ceremony,
        user: Option<&UserId>,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let id = base64url::encode(challenge);
        let issued = ChallengeEntity {
            ceremony: ceremony.as_str().to_owned(),
            user_id: user.map(|user| user.as_str().to_owned()),
            created_at: unix_secs(now)?,
        };
        retry::bounded(PASSKEY_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.create_challenge(&place, &id, &issued)
        })
        .await
    }

    /// Spend `challenge` for `ceremony` at `now`; none when it was never issued, already spent, issued for the other
    /// ceremony or past its lifetime. A challenge offered to the wrong ceremony is spent all the same.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn spend_challenge(
        &self,
        tenant: &TenantId,
        challenge: &[u8],
        ceremony: Ceremony,
        now: Timestamp,
    ) -> Result<Option<Challenged>> {
        let place = self.tenancy.place(tenant)?;
        let id = base64url::encode(challenge);
        let taken = retry::bounded(PASSKEY_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.take_challenge(&place, &id)
        })
        .await?;
        let Some(issued) = taken else {
            return Ok(None);
        };
        let lifetime =
            i64::try_from(WEBAUTHN_CHALLENGE_TTL_SECS).map_err(|_| invalid("lifetime"))?;
        let lapses_at = issued
            .created_at
            .checked_add(lifetime)
            .ok_or_else(|| unreadable("created_at"))?;
        if issued.ceremony != ceremony.as_str() || unix_secs(now)? >= lapses_at {
            return Ok(None);
        }
        let user = issued
            .user_id
            .map(|user| UserId::parse(user).map_err(|_| unreadable("user_id")))
            .transpose()?;
        Ok(Some(Challenged { user }))
    }

    /// The passkeys of `user` in `tenant`, oldest first.
    ///
    /// # Errors
    ///
    /// The store's failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn list(&self, tenant: &TenantId, user: &UserId) -> Result<Vec<ListedPasskey>> {
        let place = self.tenancy.place(tenant)?;
        let mut listed = self
            .repository
            .list_for_user(&place, user.as_str())
            .await?
            .into_iter()
            .map(|listed| {
                Ok(ListedPasskey {
                    id: answers::text_id(&listed.spelled, "passkey")?,
                    created_at: Timestamp::from_unix_secs(
                        u64::try_from(listed.passkey.created_at)
                            .map_err(|_| unreadable("created_at"))?,
                    ),
                    synced: listed.passkey.backup_eligible,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        listed.sort_by_key(|passkey| passkey.created_at.unix_secs());
        Ok(listed)
    }

    /// Remove `user`'s passkey `id` (base64url) in `tenant`; `false` when `user` holds no passkey by that id.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn remove(&self, tenant: &TenantId, user: &UserId, id: &str) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        // A credential id has one owner for as long as it exists, so the owner read here is the one deleted.
        let owned = self
            .repository
            .find_passkey(&place, id)
            .await?
            .is_some_and(|passkey| passkey.user_id == user.as_str());
        if !owned {
            return Ok(false);
        }
        Ok(self.repository.take_passkey(&place, id).await?.is_some())
    }
}
