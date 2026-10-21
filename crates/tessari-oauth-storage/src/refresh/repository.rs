//! What the refresh service needs from a backend: queries only, every decision is the service's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::{FamilyEntity, TokenEntity};
use crate::Result;

/// Storage of families and their tokens, each under its digest.
#[async_trait]
pub(crate) trait RefreshRepository: Send + Sync {
    /// Create a family and its first token together, or neither.
    async fn start(
        &self,
        place: &Place,
        family_id: &str,
        family: &FamilyEntity,
        token_id: &str,
        token: &TokenEntity,
    ) -> Result<()>;

    /// Create the family `id` with no token, refused when it exists.
    async fn create_family(&self, place: &Place, id: &str, family: &FamilyEntity) -> Result<()>;

    /// The token at `id`, if any.
    async fn find_token(&self, place: &Place, id: &str) -> Result<Option<TokenEntity>>;

    /// The family at `id`, if any.
    async fn find_family(&self, place: &Place, id: &str) -> Result<Option<FamilyEntity>>;

    /// Spend `spent` only while it is unspent and create `next` in the same transaction — both or neither.
    async fn rotate(
        &self,
        place: &Place,
        spent: &str,
        at: i64,
        next_id: &str,
        next: &TokenEntity,
    ) -> Result<()>;

    /// Mark the family revoked only while it is not; refused by the store when it already is.
    async fn revoke_family(&self, place: &Place, id: &str, at: i64, reason: &str) -> Result<()>;
}
