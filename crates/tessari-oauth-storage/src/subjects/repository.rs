//! What the subject service needs from a backend: write a secret once, read one by purpose.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::SecretEntity;
use crate::Result;

/// The tenant's sealed secrets.
#[async_trait]
pub(crate) trait SecretRepository: Send + Sync {
    /// Write `secret` under `purpose`, refused when one is already there.
    async fn create(&self, place: &Place, purpose: &str, secret: &SecretEntity) -> Result<()>;

    /// The secret kept for `purpose`, when there is one.
    async fn find(&self, place: &Place, purpose: &str) -> Result<Option<SecretEntity>>;
}
