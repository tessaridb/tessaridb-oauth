//! What the client service needs from a backend: write a registration once, move its addresses, read one by id or
//! a page in id order.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::ClientEntity;
use crate::Result;

/// The client registrations.
#[async_trait]
pub(crate) trait ClientRepository: Send + Sync {
    /// Write `client`, refused when its id is already registered.
    async fn create(&self, place: &Place, client: &ClientEntity) -> Result<()>;

    /// Point the registered `client_id` at `redirect_uris` and `resources`, refused when it is not registered.
    async fn retarget(
        &self,
        place: &Place,
        client_id: &str,
        redirect_uris: &[String],
        resources: &[String],
    ) -> Result<()>;

    /// At most `count` registrations after `after` in id order.
    async fn page(
        &self,
        place: &Place,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<ClientEntity>>;

    /// The registration of `client_id`, when there is one.
    async fn find(&self, place: &Place, client_id: &str) -> Result<Option<ClientEntity>>;
}
