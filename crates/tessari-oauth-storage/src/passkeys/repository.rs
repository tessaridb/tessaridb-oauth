//! What the passkey service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::{ChallengeEntity, PasskeyEntity};
use crate::Result;

/// Credentials and their challenges.
#[async_trait]
pub(crate) trait PasskeyRepository: Send + Sync {
    /// Write `passkey` under `id`, refused when a credential with that id exists.
    async fn create_passkey(&self, place: &Place, id: &str, passkey: &PasskeyEntity) -> Result<()>;

    /// The credential under `id`, when there is one.
    async fn find_passkey(&self, place: &Place, id: &str) -> Result<Option<PasskeyEntity>>;

    /// Move the counter of `id` to `count` when it is below it; refused otherwise.
    async fn advance_count(&self, place: &Place, id: &str, count: i64) -> Result<()>;

    /// Write `challenge` under `id`, refused when it exists.
    async fn create_challenge(
        &self,
        place: &Place,
        id: &str,
        challenge: &ChallengeEntity,
    ) -> Result<()>;

    /// Delete the challenge under `id`, answering what it held when there was one.
    async fn take_challenge(&self, place: &Place, id: &str) -> Result<Option<ChallengeEntity>>;
}
