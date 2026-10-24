//! What the key service needs from a backend: queries only, every decision is the service's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::KeyEntity;
use crate::Result;

/// Storage of a tenant's signing keys under their thumbprint.
#[async_trait]
pub(crate) trait KeyRepository: Send + Sync {
    /// Write a new key; refused by the store when one already exists under its `kid`.
    async fn create(&self, place: &Place, key: &KeyEntity) -> Result<()>;

    /// Every key not yet retired, oldest first.
    async fn live(&self, place: &Place) -> Result<Vec<KeyEntity>>;

    /// Set `retired_at` on `kid` while it is unset.
    async fn retire(&self, place: &Place, kid: &str, at: i64) -> Result<()>;

    /// Mark `kid` compromised.
    async fn compromise(&self, place: &Place, kid: &str) -> Result<()>;
}
