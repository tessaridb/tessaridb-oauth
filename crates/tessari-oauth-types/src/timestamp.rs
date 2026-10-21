//! An instant, in whole seconds since the Unix epoch, as the protocol's expiry and issuance times are.

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
