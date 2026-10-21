//! An instant, in whole seconds since the Unix epoch, as the protocol's expiry and issuance times are, and the clock
//! that supplies one.

use std::sync::Arc;

/// The clock a runtime surface reads the time from: the system clock in the server, a fixed one in tests.
pub type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

/// An instant in Unix seconds. The protocol core receives it from a clock port and never reads the system clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The instant `seconds` after the Unix epoch.
    #[must_use]
    pub const fn from_unix_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub const fn unix_secs(self) -> u64 {
        self.0
    }
}
