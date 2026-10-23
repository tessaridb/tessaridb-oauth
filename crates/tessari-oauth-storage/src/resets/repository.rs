//! What the reset service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::ResetEntity;
use crate::Result;

/// Reset tokens.
#[async_trait]
pub(crate) trait ResetRepository: Send + Sync {
    /// Remove every token of the entity's user and record `entity` under `digest`, in one transaction.
    async fn issue(&self, place: &Place, digest: &str, entity: &ResetEntity) -> Result<()>;

    /// The token under `digest`, left in place.
    async fn find(&self, place: &Place, digest: &str) -> Result<Option<ResetEntity>>;

    /// Delete the token under `digest`, answering what it held when there was one.
    async fn redeem(&self, place: &Place, digest: &str) -> Result<Option<ResetEntity>>;

    /// Delete every token of `user_id`.
    async fn cancel(&self, place: &Place, user_id: &str) -> Result<()>;
}
