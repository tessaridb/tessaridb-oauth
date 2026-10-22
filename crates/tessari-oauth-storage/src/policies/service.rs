//! A company's policies as the rest of the server asks for them.

use std::sync::Arc;

use tessari_oauth_core::two_factor::TwoFactorPolicy;
use tessari_oauth_types::{ErrorCategory, TenantId};

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
}
