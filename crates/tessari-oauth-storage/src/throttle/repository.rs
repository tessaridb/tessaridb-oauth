//! What the throttle service needs from a backend: a counter that counts and expires, every decision is the
//! service's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use crate::Result;

/// The request counters.
#[async_trait]
pub(crate) trait ThrottleRepository: Send + Sync {
    /// Make the counters exist at `place`; running it again changes nothing.
    async fn prepare(&self, place: &Place) -> Result<()>;

    /// Add one to the counter `key`, created to live `seconds` when absent, answering its new count.
    async fn count(&self, place: &Place, key: &str, seconds: u64) -> Result<u64>;
}
