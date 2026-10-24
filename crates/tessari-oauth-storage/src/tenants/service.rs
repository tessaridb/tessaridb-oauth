//! The tenant service: the only way a tenant's storage comes into existence.

use std::sync::Arc;

use tessari_oauth_types::TenantId;

use super::repository::TenantRepository;
use crate::{Result, Tenancy};

/// Tenant provisioning.
#[derive(Clone)]
pub struct TenantService {
    repository: Arc<dyn TenantRepository>,
    tenancy: Tenancy,
}

impl TenantService {
    pub(crate) fn new(repository: Arc<dyn TenantRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Make `tenant`'s database and tables exist; running it again changes nothing.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses a definition.
    pub async fn provision(&self, tenant: &TenantId) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.repository.provision(&place).await
    }
}
