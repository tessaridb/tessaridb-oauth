//! What the address-change service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::EmailChangeEntity;
use crate::Result;

/// Requested address changes.
#[async_trait]
pub(crate) trait EmailChangeRepository: Send + Sync {
    /// Remove every change of the entity's user and record `entity` under `digest`, in one transaction.
    async fn issue(&self, place: &Place, digest: &str, entity: &EmailChangeEntity) -> Result<()>;

    /// Mark the change under `digest` confirmed at `now` when it is unconfirmed and was asked for at or after
    /// `since`, answering it as it became; `None` when there is no such change.
    async fn confirm(
        &self,
        place: &Place,
        digest: &str,
        now: i64,
        since: i64,
    ) -> Result<Option<EmailChangeEntity>>;

    /// Delete the change whose cancel digest is `cancel`, answering what it held when there was one.
    async fn cancel(&self, place: &Place, cancel: &str) -> Result<Option<EmailChangeEntity>>;

    /// Up to `limit` confirmed changes asked for at or before `before`.
    async fn due(&self, place: &Place, before: i64, limit: u32) -> Result<Vec<EmailChangeEntity>>;

    /// In one transaction: delete the confirmed change `id`, give `new` to `user_id`, verified at `verified_at`, and
    /// take `old` from that user. Refused as a conflict, changing nothing, when `new` belongs to an account or `old`
    /// is no longer the user's.
    async fn apply(
        &self,
        place: &Place,
        id: &str,
        user_id: &str,
        addresses: (&str, &str),
        verified_at: i64,
    ) -> Result<()>;

    /// Delete the change `id`.
    async fn discard(&self, place: &Place, id: &str) -> Result<()>;
}
