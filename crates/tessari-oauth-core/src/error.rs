//! Failures of `tessari-oauth-core`.
//!
//! Nothing in this crate can fail yet, so the enum has no variants; each one arrives with the operation that
//! produces it, mapped to its category in the workspace taxonomy.

use tessari_oauth_types::ErrorCategory;

/// A failure of this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {}

impl Error {
    /// The taxonomy category of this failure.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match *self {}
    }
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
