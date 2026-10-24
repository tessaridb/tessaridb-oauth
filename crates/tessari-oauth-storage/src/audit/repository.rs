//! What the audit service needs from a backend: append, and read in order. There is no path that changes a message.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::AuditEntity;
use super::entity::AuditMessageEntity;
use crate::Result;

/// The trail.
#[async_trait]
pub(crate) trait AuditRepository: Send + Sync {
    /// Append `message` as `id`; refused when `id` is taken.
    async fn append(&self, place: &Place, id: &str, message: &AuditEntity) -> Result<()>;

    /// At most `limit` messages after position `after`, in order.
    async fn read_after(
        &self,
        place: &Place,
        after: u64,
        limit: u64,
    ) -> Result<Vec<AuditMessageEntity>>;
}
