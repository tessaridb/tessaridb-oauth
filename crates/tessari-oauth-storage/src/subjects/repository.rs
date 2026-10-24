//! What the subject service needs from a backend: write a secret once, read one by purpose; record whom a derived
//! subject stands for, once, and read it back.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::{SecretEntity, SubjectEntity};
use crate::Result;

/// The tenant's sealed secrets.
#[async_trait]
pub(crate) trait SecretRepository: Send + Sync {
    /// Write `secret` under `purpose`, refused when one is already there.
    async fn create(&self, place: &Place, purpose: &str, secret: &SecretEntity) -> Result<()>;

    /// The secret kept for `purpose`, when there is one.
    async fn find(&self, place: &Place, purpose: &str) -> Result<Option<SecretEntity>>;

    /// Record whom `subject` stands for, refused when it is recorded already.
    async fn create_subject(
        &self,
        place: &Place,
        subject: &str,
        entity: &SubjectEntity,
    ) -> Result<()>;

    /// Whom `subject` stands for, when it is recorded.
    async fn find_subject(&self, place: &Place, subject: &str) -> Result<Option<SubjectEntity>>;
}
