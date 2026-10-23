//! What the outbox service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::MailEntity;
use super::entity::ClaimedEntity;
use crate::Result;

/// Queued mail.
#[async_trait]
pub(crate) trait OutboxRepository: Send + Sync {
    /// Queue the mail sealed as `sealed` under `id`, due now.
    async fn enqueue(&self, place: &Place, id: &str, sealed: &str) -> Result<()>;

    /// Claim at most `count` mails that are due and held by nobody.
    async fn claim(&self, place: &Place, count: u32) -> Result<Vec<ClaimedEntity>>;

    /// Release the mail under `id`, due again `after_secs` from now.
    async fn retry(&self, place: &Place, id: &str, after_secs: i64) -> Result<()>;

    /// Delete the mail under `id`, answering what it held when there was one.
    async fn finish(&self, place: &Place, id: &str) -> Result<Option<MailEntity>>;
}
