//! What the session service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::SessionEntity;
use super::entity::ListedSessionEntity;
use crate::Result;

/// Sessions.
#[async_trait]
pub(crate) trait SessionRepository: Send + Sync {
    /// Write `session` under `id`, refused when one exists.
    async fn create(&self, place: &Place, id: &str, session: &SessionEntity) -> Result<()>;

    /// The session under `id`, when there is one.
    async fn find(&self, place: &Place, id: &str) -> Result<Option<SessionEntity>>;

    /// Record that the session under `id` was found at `seen_at`.
    async fn touch(&self, place: &Place, id: &str, seen_at: i64) -> Result<()>;

    /// Delete the session under `id`, answering what it held when there was one.
    async fn take(&self, place: &Place, id: &str) -> Result<Option<SessionEntity>>;

    /// Every session of `user_id` the store still holds, with its id.
    async fn list_for_user(&self, place: &Place, user_id: &str)
    -> Result<Vec<ListedSessionEntity>>;
}
