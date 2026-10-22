//! The enrolment service: an operator issues a user one code at a time, and the code is spent once.

use std::sync::Arc;

use tessari_oauth_types::{EnrolmentCode, TenantId, Timestamp, UserId};

use super::EnrolmentEntity;
use super::repository::EnrolmentRepository;
use crate::{Error, Result, Tenancy};

/// Enrolment codes in every tenant of a region.
pub struct EnrolmentService {
    repository: Arc<dyn EnrolmentRepository>,
    tenancy: Tenancy,
}

impl EnrolmentService {
    pub(crate) fn new(repository: Arc<dyn EnrolmentRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Record `code` as `user`'s only enrolment code in `tenant`, issued by `by` at `now`; any earlier code of that
    /// user stops working.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] for a time past the store's range.
    pub async fn issue(
        &self,
        tenant: &TenantId,
        code: &EnrolmentCode,
        user: &UserId,
        by: &str,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let created_at = i64::try_from(now.unix_secs()).map_err(|_| Error::Invalid {
            record: "enrolment",
            reason: "an issue time past the store's range",
        })?;
        let entity = EnrolmentEntity {
            user_id: user.as_str().to_owned(),
            created_at,
            created_by: by.to_owned(),
        };
        self.repository.issue(&place, &code.digest(), &entity).await
    }

    /// Spend `code` in `tenant`: the user it enrols, once; `None` for a code that was never issued, was spent, was
    /// replaced or has lapsed.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn redeem(&self, tenant: &TenantId, code: &EnrolmentCode) -> Result<Option<UserId>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .redeem(&place, &code.digest())
            .await?
            .map(|entity| {
                UserId::parse(entity.user_id).map_err(|_| Error::Unreadable {
                    record: "enrolment",
                    reason: "user_id".to_owned(),
                })
            })
            .transpose()
    }
}
