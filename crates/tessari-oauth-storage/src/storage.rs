//! The storage aggregate: every domain's service, assembled in one place.

use std::sync::Arc;

use tessari_oauth_infrastructure::tessaridb::Database;

use crate::Tenancy;
use crate::codes::{CodeService, TessaridbCodeRepository};
use crate::consents::{ConsentService, TessaridbConsentRepository};
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
}

impl Storage {
    /// Assemble the services over `database`, for the region `tenancy` names.
    #[must_use]
    pub fn new(database: &Database, tenancy: &Tenancy) -> Self {
        let tenant_repository = Arc::new(TessaridbTenantRepository::new(database.clone()));
        let code_repository = Arc::new(TessaridbCodeRepository::new(database.clone()));
        let consent_repository = Arc::new(TessaridbConsentRepository::new(database.clone()));
        Self {
            tenants: Arc::new(TenantService::new(tenant_repository, tenancy.clone())),
            codes: Arc::new(CodeService::new(code_repository, tenancy.clone())),
            consents: Arc::new(ConsentService::new(consent_repository, tenancy.clone())),
        }
    }
}
