//! What the verification service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::VerificationEntity;
use crate::Result;

/// Verification tokens.
#[async_trait]
pub(crate) trait VerificationRepository: Send + Sync {
    /// Remove every token of the entity's user and record `entity` under `digest`, in one transaction.
    async fn issue(&self, place: &Place, digest: &str, entity: &VerificationEntity) -> Result<()>;

    /// Delete the token under `digest`, answering what it held when there was one.
    async fn redeem(&self, place: &Place, digest: &str) -> Result<Option<VerificationEntity>>;
}
