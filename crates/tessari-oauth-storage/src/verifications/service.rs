//! The verification service: a token issued for one account and the address it was sent to, spent once.

use std::sync::Arc;

use tessari_oauth_types::{EmailAddress, TenantId, Timestamp, UserId, VerifyToken};

use super::VerificationEntity;
use super::repository::VerificationRepository;
use crate::{Error, Result, Tenancy};

/// Address-verification tokens.
pub struct VerificationService {
    repository: Arc<dyn VerificationRepository>,
    tenancy: Tenancy,
}

impl VerificationService {
    pub(crate) fn new(repository: Arc<dyn VerificationRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Record `token` as `user`'s only verification token in `tenant`, sent to `address` at `now`; any earlier token
    /// of that user stops working.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] for a time past the store's range.
    pub async fn issue(
        &self,
        tenant: &TenantId,
        token: &VerifyToken,
        user: &UserId,
        address: &EmailAddress,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let created_at = i64::try_from(now.unix_secs()).map_err(|_| Error::Invalid {
            record: "address verification",
            reason: "an issue time past the store's range",
        })?;
        let entity = VerificationEntity {
            user_id: user.as_str().to_owned(),
            address: address.as_str().to_owned(),
            created_at,
        };
        self.repository
            .issue(&place, &token.digest(), &entity)
            .await
    }

    /// Spend `token` in `tenant`: the account and the address it was sent for, once; `None` for a token that was never
    /// issued, was spent, was replaced or has lapsed.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn redeem(
        &self,
        tenant: &TenantId,
        token: &VerifyToken,
    ) -> Result<Option<(UserId, EmailAddress)>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .redeem(&place, &token.digest())
            .await?
            .map(claim)
            .transpose()
    }
}

/// The account and the address a stored token was sent for.
fn claim(entity: VerificationEntity) -> Result<(UserId, EmailAddress)> {
    let unreadable = |field: &str| Error::Unreadable {
        record: "address verification",
        reason: field.to_owned(),
    };
    let user = UserId::parse(entity.user_id).map_err(|_| unreadable("user_id"))?;
    let address = EmailAddress::parse(&entity.address).map_err(|_| unreadable("address"))?;
    Ok((user, address))
}
