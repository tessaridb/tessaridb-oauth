//! What the operator service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::OperatorGrantEntity;
use crate::Result;

/// Operator grants.
#[async_trait]
pub(crate) trait OperatorRepository: Send + Sync {
    /// Record `entity` under `id`, replacing what was there.
    async fn put(&self, place: &Place, id: &str, entity: &OperatorGrantEntity) -> Result<()>;

    /// Delete the grant under `id`, answering what it held when there was one.
    async fn delete(&self, place: &Place, id: &str) -> Result<Option<OperatorGrantEntity>>;

    /// At most `limit` grants of `user` that have not expired at `now`.
    async fn current(
        &self,
        place: &Place,
        user: &str,
        now: i64,
        limit: i64,
    ) -> Result<Vec<OperatorGrantEntity>>;
}
