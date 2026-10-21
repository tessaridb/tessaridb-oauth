//! What the code service needs from a backend: queries only, every decision is the service's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::CodeEntity;
use crate::Result;

/// Storage of issued codes under their digest.
#[async_trait]
pub(crate) trait CodeRepository: Send + Sync {
    /// Write a new code; refused by the store when one already exists at `digest`.
    async fn create(&self, place: &Place, digest: &str, code: &CodeEntity) -> Result<()>;

    /// The code at `digest`, if any.
    async fn find(&self, place: &Place, digest: &str) -> Result<Option<CodeEntity>>;

    /// Set `redeemed_at` only while it is absent, answering the row as it stood before. A code already redeemed is
    /// a refusal from the store, because the condition is a compare-and-set rather than a filter.
    async fn mark_redeemed(
        &self,
        place: &Place,
        digest: &str,
        at: i64,
    ) -> Result<Option<CodeEntity>>;
}
