//! What the assertion service needs from a backend: one conditional write, every decision is the service's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use crate::Result;

/// The record of spent assertions.
#[async_trait]
pub(crate) trait AssertionRepository: Send + Sync {
    /// Record `key` for `seconds` unless it is already recorded, answering whether this call recorded it.
    async fn record_if_absent(&self, place: &Place, key: &str, seconds: u64) -> Result<bool>;
}
