//! What the tenant service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use crate::Result;

/// Provisions the place a tenant's records live in.
#[async_trait]
pub(crate) trait TenantRepository: Send + Sync {
    /// Declare the namespace and the database, then every table in one transaction, each only if absent.
    async fn provision(&self, place: &Place) -> Result<()>;
}
