//! What the consent service needs from a backend: queries only, every decision is the service's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::ConsentEntity;
use crate::Result;

/// Storage of consent records under their user × client id.
#[async_trait]
pub(crate) trait ConsentRepository: Send + Sync {
    /// Write the first record for an id; refused by the store when one exists.
    async fn create(&self, place: &Place, id: &str, consent: &ConsentEntity) -> Result<()>;

    /// Overwrite the grant only while the stored revision is still `seen`; refused otherwise, because the
    /// condition is a compare-and-set rather than a filter.
    async fn replace(
        &self,
        place: &Place,
        id: &str,
        consent: &ConsentEntity,
        seen: i64,
    ) -> Result<()>;

    /// The record at `id`, if any.
    async fn find(&self, place: &Place, id: &str) -> Result<Option<ConsentEntity>>;

    /// Every record of `user_id`, revoked ones included.
    async fn list_for_user(&self, place: &Place, user_id: &str) -> Result<Vec<ConsentEntity>>;

    /// Every record of `client_id`, revoked ones included.
    async fn list_for_client(&self, place: &Place, client_id: &str) -> Result<Vec<ConsentEntity>>;

    /// Mark the record revoked only while it is not, answering it as it stood before.
    async fn revoke(
        &self,
        place: &Place,
        id: &str,
        at: i64,
        by: &str,
    ) -> Result<Option<ConsentEntity>>;
}
