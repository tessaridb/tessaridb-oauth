//! What the service credential service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::ServiceEntity;
use crate::Result;

/// Registered services.
#[async_trait]
pub(crate) trait ServiceRepository: Send + Sync {
    /// Record `entity` under its id; refused as a conflict when the id is taken.
    async fn create(&self, place: &Place, entity: &ServiceEntity) -> Result<()>;

    /// The service under `id`.
    async fn find(&self, place: &Place, id: &str) -> Result<Option<ServiceEntity>>;

    /// At most `count` services in id order.
    async fn list(&self, place: &Place, count: i64) -> Result<Vec<ServiceEntity>>;

    /// Delete the service under `id`, answering what it held when there was one.
    async fn delete(&self, place: &Place, id: &str) -> Result<Option<ServiceEntity>>;
}
