//! A company's policies as the rest of the server asks for them.

use std::sync::Arc;

use tessari_oauth_core::registration::RegistrationPolicy;
use tessari_oauth_core::two_factor::TwoFactorPolicy;
use tessari_oauth_types::{ErrorCategory, TenantId};

use super::RegistrationEntity;
use super::repository::PolicyRepository;
use crate::{Error, Result, Tenancy};

/// Reads and sets each company's policies.
pub struct PolicyService {
    repository: Arc<dyn PolicyRepository>,
    tenancy: Tenancy,
}

impl PolicyService {
    pub(crate) fn new(repository: Arc<dyn PolicyRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// `tenant`'s two-factor policy; optional until one is set.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored value no policy is named.
    pub async fn two_factor(&self, tenant: &TenantId) -> Result<TwoFactorPolicy> {
        let place = self.tenancy.place(tenant)?;
        match self.repository.find_two_factor(&place).await? {
            None => Ok(TwoFactorPolicy::default()),
            Some(stored) => {
                TwoFactorPolicy::named(&stored.policy).ok_or_else(|| Error::Unreadable {
                    record: "two-factor policy",
                    reason: "a policy no name stands for".to_owned(),
                })
            }
        }
    }

    /// Set `tenant`'s two-factor policy to `policy`.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn set_two_factor(&self, tenant: &TenantId, policy: TwoFactorPolicy) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.repository.put_two_factor(&place, policy.name()).await
    }

    /// Set `tenant`'s two-factor policy to `policy` only while it is still `expected`; `false`, changing nothing, when it
    /// is not, because somebody changed it since it was read.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored value no policy is named.
    pub async fn set_two_factor_if(
        &self,
        tenant: &TenantId,
        expected: TwoFactorPolicy,
        policy: TwoFactorPolicy,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let stored = self.repository.find_two_factor(&place).await?;
        let current = match &stored {
            None => TwoFactorPolicy::default(),
            Some(stored) => {
                TwoFactorPolicy::named(&stored.policy).ok_or_else(|| Error::Unreadable {
                    record: "two-factor policy",
                    reason: "a policy no name stands for".to_owned(),
                })?
            }
        };
        if current != expected {
            return Ok(false);
        }
        let written = match stored {
            None => {
                self.repository
                    .create_two_factor(&place, policy.name())
                    .await
            }
            Some(_) => {
                self.repository
                    .replace_two_factor(&place, expected.name(), policy.name())
                    .await
            }
        };
        match written {
            Ok(()) => Ok(true),
            // Created or changed between the read and the write.
            Err(refused) if refused.category() == ErrorCategory::Conflict => Ok(false),
            Err(failure) => Err(failure),
        }
    }

    /// `tenant`'s registration policy and the revision a change names; closed at revision 0 until one is kept.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored policy the rules refuse or a negative revision.
    pub async fn registration(&self, tenant: &TenantId) -> Result<(RegistrationPolicy, u64)> {
        let place = self.tenancy.place(tenant)?;
        let Some(stored) = self.repository.find_registration(&place).await? else {
            return Ok((RegistrationPolicy::default(), 0));
        };
        let unreadable = |reason: &str| Error::Unreadable {
            record: "registration policy",
            reason: reason.to_owned(),
        };
        let revision =
            u64::try_from(stored.revision).map_err(|_| unreadable("a negative revision"))?;
        let policy = RegistrationPolicy::new(stored.open, stored.domains)
            .map_err(|_| unreadable("domains the rules refuse"))?;
        Ok((policy, revision))
    }

    /// Keep `policy` as `tenant`'s registration policy only while the kept one is still at `replaces` (0 when none
    /// is kept): its new revision, or `None`, changing nothing, when somebody changed it since it was read.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a revision past what the store holds.
    pub async fn set_registration(
        &self,
        tenant: &TenantId,
        replaces: u64,
        policy: &RegistrationPolicy,
    ) -> Result<Option<u64>> {
        let place = self.tenancy.place(tenant)?;
        let revision = replaces.checked_add(1).ok_or_else(|| Error::Unreadable {
            record: "registration policy",
            reason: "a revision past the last".to_owned(),
        })?;
        let entity = RegistrationEntity {
            open: policy.is_open(),
            domains: policy.domains().to_vec(),
            revision: i64::try_from(revision).map_err(|_| Error::Unreadable {
                record: "registration policy",
                reason: "a revision past the last".to_owned(),
            })?,
        };
        let written = if replaces == 0 {
            self.repository.create_registration(&place, &entity).await
        } else {
            let replaced = i64::try_from(replaces).map_err(|_| Error::Unreadable {
                record: "registration policy",
                reason: "a revision past the last".to_owned(),
            })?;
            self.repository
                .replace_registration(&place, replaced, &entity)
                .await
        };
        match written {
            Ok(()) => Ok(Some(revision)),
            // Kept, or changed, between the read and the write.
            Err(refused) if refused.category() == ErrorCategory::Conflict => Ok(None),
            Err(failure) => Err(failure),
        }
    }
}
