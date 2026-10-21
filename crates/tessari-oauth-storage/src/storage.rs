//! The storage aggregate: every domain's service, assembled in one place.

use std::sync::Arc;

use tessari_oauth_infrastructure::tessaridb::Database;

use crate::Tenancy;
use crate::assertions::{AssertionService, TessaridbAssertionRepository};
use crate::codes::{CodeService, TessaridbCodeRepository};
use crate::consents::{ConsentService, TessaridbConsentRepository};
use crate::refresh::{RefreshService, TessaridbRefreshRepository};
use crate::tenants::{TenantService, TessaridbTenantRepository};

/// The services the server reaches its records through.
#[derive(Clone)]
pub struct Storage {
    /// Tenant provisioning.
    pub tenants: Arc<TenantService>,
    /// Authorization codes.
    pub codes: Arc<CodeService>,
    /// Users' grants to clients.
    pub consents: Arc<ConsentService>,
    /// Refresh-token families.
    pub refresh: Arc<RefreshService>,
    /// Spent client assertions.
    pub assertions: Arc<AssertionService>,
}

impl Storage {
    /// Assemble the services over `database`, for the region `tenancy` names.
    #[must_use]
    pub fn new(database: &Database, tenancy: &Tenancy) -> Self {
        let tenant_repository = Arc::new(TessaridbTenantRepository::new(database.clone()));
        let code_repository = Arc::new(TessaridbCodeRepository::new(database.clone()));
        let consent_repository = Arc::new(TessaridbConsentRepository::new(database.clone()));
        let refresh_repository = Arc::new(TessaridbRefreshRepository::new(database.clone()));
        let assertion_repository = Arc::new(TessaridbAssertionRepository::new(database.clone()));
        Self {
            tenants: Arc::new(TenantService::new(tenant_repository, tenancy.clone())),
            codes: Arc::new(CodeService::new(code_repository, tenancy.clone())),
            consents: Arc::new(ConsentService::new(consent_repository, tenancy.clone())),
            refresh: Arc::new(RefreshService::new(refresh_repository, tenancy.clone())),
            assertions: Arc::new(AssertionService::new(assertion_repository, tenancy.clone())),
        }
    }
}
