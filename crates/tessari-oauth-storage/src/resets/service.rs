//! The reset service: a token issued for one account, found without spending it, spent once, and cancelled when the
//! account signs in.

use std::sync::Arc;

use tessari_oauth_types::{ResetToken, TenantId, Timestamp, UserId};

use super::ResetEntity;
use super::repository::ResetRepository;
use crate::{Error, Result, Tenancy};

/// Password-reset tokens.
pub struct ResetService {
    repository: Arc<dyn ResetRepository>,
    tenancy: Tenancy,
}

impl ResetService {
    pub(crate) fn new(repository: Arc<dyn ResetRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Record `token` as `user`'s only reset token in `tenant`, issued at `now`; any earlier token of that user stops
    /// working.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] for a time past the store's range.
    pub async fn issue(
        &self,
        tenant: &TenantId,
        token: &ResetToken,
        user: &UserId,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let created_at = i64::try_from(now.unix_secs()).map_err(|_| Error::Invalid {
            record: "password reset",
            reason: "an issue time past the store's range",
        })?;
        let entity = ResetEntity {
            user_id: user.as_str().to_owned(),
            created_at,
        };
        self.repository
            .issue(&place, &token.digest(), &entity)
            .await
    }

    /// The user `token` would reset in `tenant`, without spending it; `None` as for [`Self::redeem`].
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn find(&self, tenant: &TenantId, token: &ResetToken) -> Result<Option<UserId>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .find(&place, &token.digest())
            .await?
            .map(user)
            .transpose()
    }

    /// Spend `token` in `tenant`: the user it resets, once; `None` for a token that was never issued, was spent, was
    /// replaced, was cancelled or has lapsed.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn redeem(&self, tenant: &TenantId, token: &ResetToken) -> Result<Option<UserId>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .redeem(&place, &token.digest())
            .await?
            .map(user)
            .transpose()
    }

    /// Stop every reset token of `user` in `tenant` working: the account signed in, so its owner holds it.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn cancel(&self, tenant: &TenantId, user: &UserId) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.repository.cancel(&place, user.as_str()).await
    }
}

/// The user a stored token resets.
fn user(entity: ResetEntity) -> Result<UserId> {
    UserId::parse(entity.user_id).map_err(|_| Error::Unreadable {
        record: "password reset",
        reason: "user_id".to_owned(),
    })
}
