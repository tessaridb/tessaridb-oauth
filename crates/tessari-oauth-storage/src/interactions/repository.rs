//! What the interaction service needs from a backend: write one, read one by id, claim a pushed one.

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

    /// Set `claimed_at` to `at` on the interaction at `id` in one conditional write, if it is unclaimed and was made
    /// by `client_id`, answering it as it stood before. One that is claimed already or another client's is a refusal
    /// from the store, because the condition is a compare-and-set rather than a filter.
    async fn claim(
        &self,
        place: &Place,
        id: &str,
        client_id: &str,
        at: i64,
    ) -> Result<Option<InteractionEntity>>;
}
