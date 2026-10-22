//! What the enrolment service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::EnrolmentEntity;
use crate::Result;

/// Enrolment codes.
#[async_trait]
pub(crate) trait EnrolmentRepository: Send + Sync {
    /// Remove every code of the entity's user and record `entity` under `digest`, in one transaction.
    async fn issue(&self, place: &Place, digest: &str, entity: &EnrolmentEntity) -> Result<()>;

    /// The code under `digest`, left in place.
    async fn find(&self, place: &Place, digest: &str) -> Result<Option<EnrolmentEntity>>;

    /// Delete the code under `digest`, answering what it held when there was one.
    async fn redeem(&self, place: &Place, digest: &str) -> Result<Option<EnrolmentEntity>>;
}
