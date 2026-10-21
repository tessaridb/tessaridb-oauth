//! What the client service needs from a backend: write a registration once, read one by id.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::ClientEntity;
use crate::Result;

/// The client registrations.
#[async_trait]
pub(crate) trait ClientRepository: Send + Sync {
    /// Write `client`, refused when its id is already registered.
    async fn create(&self, place: &Place, client: &ClientEntity) -> Result<()>;

    /// The registration of `client_id`, when there is one.
    async fn find(&self, place: &Place, client_id: &str) -> Result<Option<ClientEntity>>;
}
