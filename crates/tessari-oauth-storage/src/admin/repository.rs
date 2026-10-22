//! What the admin service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::{AdminActionEntity, AdminSessionEntity, PendingSigninEntity};
use crate::Result;

/// Admin sign-ins in progress and admin sessions.
#[async_trait]
pub(crate) trait AdminRepository: Send + Sync {
    /// Write `pending` under `id`, refused when one exists.
    async fn begin(&self, place: &Place, id: &str, pending: &PendingSigninEntity) -> Result<()>;

    /// Delete the sign-in under `id`, answering what it held when there was one.
    async fn take(&self, place: &Place, id: &str) -> Result<Option<PendingSigninEntity>>;

    /// Write `session` under `id`, refused when one exists.
    async fn open(&self, place: &Place, id: &str, session: &AdminSessionEntity) -> Result<()>;

    /// The session under `id`, when there is one.
    async fn find(&self, place: &Place, id: &str) -> Result<Option<AdminSessionEntity>>;

    /// Record that the session under `id` was found at `seen_at`.
    async fn touch(&self, place: &Place, id: &str, seen_at: i64) -> Result<()>;

    /// Delete the session under `id`, answering what it held when there was one.
    async fn end(&self, place: &Place, id: &str) -> Result<Option<AdminSessionEntity>>;

    /// Write `action` under `id`, refused when one exists.
    async fn claim(&self, place: &Place, id: &str, action: &AdminActionEntity) -> Result<()>;

    /// The change under `id`, when there is one.
    async fn action(&self, place: &Place, id: &str) -> Result<Option<AdminActionEntity>>;

    /// Record the answer the change under `id` was given.
    async fn finish(&self, place: &Place, id: &str, status: i64, answer: &str) -> Result<()>;

    /// Delete the change under `id`.
    async fn release(&self, place: &Place, id: &str) -> Result<()>;
}
