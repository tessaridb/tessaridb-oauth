//! What a re-seal needs from a backend: queries only, every decision is the service's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::entity::SealedEntity;
use super::model::Family;
use crate::Result;

/// The sealed values of one family's table.
#[async_trait]
pub(crate) trait SealedRepository: Send + Sync {
    /// At most `count` of the table's records in id order, after the record `after` when it is given.
    async fn page(
        &self,
        place: &Place,
        family: Family,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<SealedEntity>>;

    /// Replace the sealed value of `id` with `new` while it still holds `old`; the store refuses otherwise.
    async fn replace(
        &self,
        place: &Place,
        family: Family,
        id: &str,
        old: &str,
        new: &str,
    ) -> Result<()>;
}
