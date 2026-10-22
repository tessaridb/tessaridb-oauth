//! What the company service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::CompanyEntity;
use super::entity::ListedEntity;
use crate::Result;

/// The directory of companies.
#[async_trait]
pub(crate) trait CompanyRepository: Send + Sync {
    /// Make the directory's database and table exist; running it again changes nothing.
    async fn prepare(&self, place: &Place) -> Result<()>;

    /// Write `company` under `id`; refused when the id is taken.
    async fn create(&self, place: &Place, id: &str, company: &CompanyEntity) -> Result<()>;

    /// The company under `id`.
    async fn find(&self, place: &Place, id: &str) -> Result<Option<CompanyEntity>>;

    /// At most `count` companies in id order, after `after` when it is given.
    async fn page(
        &self,
        place: &Place,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<ListedEntity>>;

    /// Move the company under `id` from status `from` to `to`; refused when it is not in `from` or does not exist.
    async fn transition(&self, place: &Place, id: &str, from: &str, to: &str) -> Result<()>;
}
