//! What the logout service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::DeliveryEntity;
use super::entity::ClaimedEntity;
use crate::Result;

/// Owed logouts.
#[async_trait]
pub(crate) trait LogoutRepository: Send + Sync {
    /// Claim at most `count` deliveries that are due and held by nobody.
    async fn claim(&self, place: &Place, count: u32) -> Result<Vec<ClaimedEntity>>;

    /// Delete the delivery under `id`, answering what it held when there was one.
    async fn finish(&self, place: &Place, id: &str) -> Result<Option<DeliveryEntity>>;
}
