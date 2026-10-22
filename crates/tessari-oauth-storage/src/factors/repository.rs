//! What the factor service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::TotpEntity;
use crate::Result;

/// The one-time code factors and the recovery codes.
#[async_trait]
pub(crate) trait FactorRepository: Send + Sync {
    /// Write `factor`, refused when the user already has one.
    async fn create_totp(&self, place: &Place, factor: &TotpEntity) -> Result<()>;

    /// The factor of `user_id`, when there is one.
    async fn find_totp(&self, place: &Place, user_id: &str) -> Result<Option<TotpEntity>>;

    /// Move the last accepted step of `user_id` to `step` when it is below it; refused otherwise.
    async fn advance_step(&self, place: &Place, user_id: &str, step: i64) -> Result<()>;

    /// Replace the recovery codes of `user_id` with `digests`, in one transaction.
    async fn replace_codes(
        &self,
        place: &Place,
        user_id: &str,
        digests: &[String],
        created_at: i64,
    ) -> Result<()>;

    /// Delete `user_id`'s code under `digest`; whether there was one to delete.
    async fn delete_code(&self, place: &Place, user_id: &str, digest: &str) -> Result<bool>;

    /// Whether `user_id` holds a code under `digest`.
    async fn has_code(&self, place: &Place, user_id: &str, digest: &str) -> Result<bool>;
}
