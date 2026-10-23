//! What the throttle service needs from a backend: a counter that counts and expires, every decision is the
//! service's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::model::Counters;
use crate::Result;

/// The request counters.
#[async_trait]
pub(crate) trait ThrottleRepository: Send + Sync {
    /// Make the counters exist at `place`; running it again changes nothing.
    async fn prepare(&self, place: &Place) -> Result<()>;

    /// Add one to the counter `key` in `counters`, created to live `seconds` when absent, answering its new count.
    async fn count(
        &self,
        place: &Place,
        counters: Counters,
        key: &str,
        seconds: u64,
    ) -> Result<u64>;

    /// Write `until` under `key`, living `seconds`, only while `key` holds `from` (absent when `None`); answers
    /// whether it wrote.
    async fn hold(
        &self,
        place: &Place,
        key: &str,
        from: Option<u64>,
        until: u64,
        seconds: u64,
    ) -> Result<bool>;

    /// The value under `key`, when there is one that has not expired.
    async fn held_until(&self, place: &Place, key: &str) -> Result<Option<u64>>;

    /// Remove `key`, whether or not it is there.
    async fn forget(&self, place: &Place, key: &str) -> Result<()>;
}
