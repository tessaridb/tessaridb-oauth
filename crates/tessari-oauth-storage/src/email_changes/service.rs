//! The address-change service: a change asked for by one account, confirmed once by the new address within a day,
//! cancellable by the old address until it is applied, and applied only once its hold is over.

use std::sync::Arc;

use tessari_oauth_constants::{EMAIL_CHANGE_CONFIRM_SECS, EMAIL_CHANGE_HOLD_SECS};
use tessari_oauth_types::{EmailAddress, ErrorCategory, TenantId, Timestamp, UserId, VerifyToken};

use super::repository::EmailChangeRepository;
use super::{ConfirmedChange, DueChange, EmailChangeEntity};
use crate::{Error, Result, Tenancy, answers};

/// Requested changes of a sign-in address.
pub struct EmailChangeService {
    repository: Arc<dyn EmailChangeRepository>,
    tenancy: Tenancy,
}

/// The addresses a change moves between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addresses {
    /// The address the account signs in with now.
    pub old: EmailAddress,
    /// The address it changes to.
    pub new: EmailAddress,
}

impl EmailChangeService {
    pub(crate) fn new(repository: Arc<dyn EmailChangeRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Record a change of `user`'s address in `tenant`, asked for at `now`, confirmed by the first of `tokens` and
    /// cancelled by the second; any earlier change of that user is dropped.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] for a time past the store's range.
    pub async fn issue(
        &self,
        tenant: &TenantId,
        (confirm, cancel): (&VerifyToken, &VerifyToken),
        user: &UserId,
        addresses: &Addresses,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let entity = EmailChangeEntity {
            spelled: String::new(),
            user_id: user.as_str().to_owned(),
            old_address: addresses.old.as_str().to_owned(),
            new_address: addresses.new.as_str().to_owned(),
            cancel_digest: cancel.digest(),
            created_at: seconds(now)?,
            confirmed_at: None,
        };
        self.repository
            .issue(&place, &confirm.digest(), &entity)
            .await
    }

    /// Confirm the change `token` names in `tenant` at `now`; `None` for a token that was never issued, was used,
    /// was replaced, was cancelled or is older than a day.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn confirm(
        &self,
        tenant: &TenantId,
        token: &VerifyToken,
        now: Timestamp,
    ) -> Result<Option<ConfirmedChange>> {
        let place = self.tenancy.place(tenant)?;
        let since = now.unix_secs().saturating_sub(EMAIL_CHANGE_CONFIRM_SECS);
        let confirmed = self
            .repository
            .confirm(
                &place,
                &token.digest(),
                seconds(now)?,
                seconds(Timestamp::from_unix_secs(since))?,
            )
            .await;
        let entity = match confirmed {
            Ok(Some(entity)) => entity,
            // Already confirmed, too old or never there: the condition refused it and nothing changed.
            Ok(None) => return Ok(None),
            Err(refused) if refused_as_conflict(&refused) => return Ok(None),
            Err(failure) => return Err(failure),
        };
        let created_at = u64::try_from(entity.created_at).map_err(|_| unreadable("created_at"))?;
        let effective_at = created_at
            .checked_add(EMAIL_CHANGE_HOLD_SECS)
            .ok_or_else(|| unreadable("created_at"))?;
        Ok(Some(ConfirmedChange {
            user: user_of(&entity)?,
            new_address: address(&entity.new_address, "new_address")?,
            effective_at: Timestamp::from_unix_secs(effective_at),
        }))
    }

    /// Cancel the change `token` names in `tenant`; `None` when there is none to cancel.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn cancel(
        &self,
        tenant: &TenantId,
        token: &VerifyToken,
    ) -> Result<Option<(UserId, Addresses)>> {
        let place = self.tenancy.place(tenant)?;
        let Some(entity) = self.repository.cancel(&place, &token.digest()).await? else {
            return Ok(None);
        };
        Ok(Some((user_of(&entity)?, addresses_of(&entity)?)))
    }

    /// Up to `limit` confirmed changes in `tenant` whose hold is over at `now`.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn due(
        &self,
        tenant: &TenantId,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<DueChange>> {
        let place = self.tenancy.place(tenant)?;
        let before = now.unix_secs().saturating_sub(EMAIL_CHANGE_HOLD_SECS);
        self.repository
            .due(&place, seconds(Timestamp::from_unix_secs(before))?, limit)
            .await?
            .into_iter()
            .map(|entity| {
                let Addresses { old, new } = addresses_of(&entity)?;
                Ok(DueChange {
                    id: answers::text_id(&entity.spelled, "address change")?,
                    user: user_of(&entity)?,
                    old_address: old,
                    new_address: new,
                    confirmed_at: entity
                        .confirmed_at
                        .ok_or_else(|| unreadable("confirmed_at"))?,
                })
            })
            .collect()
    }

    /// Apply `change` in `tenant`; `false`, changing nothing, when its new address belongs to an account or its old
    /// address is no longer the user's.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn apply(&self, tenant: &TenantId, change: &DueChange) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let applied = self
            .repository
            .apply(
                &place,
                &change.id,
                change.user.as_str(),
                (change.old_address.as_str(), change.new_address.as_str()),
                change.confirmed_at,
            )
            .await;
        match applied {
            Ok(()) => Ok(true),
            Err(refused) if refused_as_conflict(&refused) => Ok(false),
            Err(failure) => Err(failure),
        }
    }

    /// Drop `change` in `tenant` without applying it.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn discard(&self, tenant: &TenantId, change: &DueChange) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.repository.discard(&place, &change.id).await
    }
}

/// A refusal that is the store's condition or identity check saying no, as opposed to contention worth retrying.
fn refused_as_conflict(failure: &Error) -> bool {
    matches!(failure, Error::Store(store) if store.category() == ErrorCategory::Conflict && !store.is_retry())
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| Error::Invalid {
        record: "address change",
        reason: "a time past the store's range",
    })
}

fn unreadable(field: &str) -> Error {
    Error::Unreadable {
        record: "address change",
        reason: field.to_owned(),
    }
}

fn address(raw: &str, field: &str) -> Result<EmailAddress> {
    EmailAddress::parse(raw).map_err(|_| unreadable(field))
}

fn user_of(entity: &EmailChangeEntity) -> Result<UserId> {
    UserId::parse(entity.user_id.clone()).map_err(|_| unreadable("user_id"))
}

fn addresses_of(entity: &EmailChangeEntity) -> Result<Addresses> {
    Ok(Addresses {
        old: address(&entity.old_address, "old_address")?,
        new: address(&entity.new_address, "new_address")?,
    })
}
