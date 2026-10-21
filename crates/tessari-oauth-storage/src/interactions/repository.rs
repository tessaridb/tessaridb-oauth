//! What the interaction service needs from a backend: write one, read one by id.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::InteractionEntity;
use crate::Result;

/// Pending authorizations.
#[async_trait]
pub(crate) trait InteractionRepository: Send + Sync {
    /// Write `interaction` as `id`; refused when `id` is taken.
    async fn create(&self, place: &Place, id: &str, interaction: &InteractionEntity) -> Result<()>;

    /// The interaction at `id`, unless there is none or the store has expired it.
    async fn find(&self, place: &Place, id: &str) -> Result<Option<InteractionEntity>>;
}
