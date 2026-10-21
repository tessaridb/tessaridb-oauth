//! Failures of `tessari-oauth-types`.
//!
//! Every variant is a `validation` failure in the workspace's error taxonomy: a value from outside did not have the
//! shape its specification gives it. [`Error::category`] names it so callers route on the category, never on the
//! message, and [`Error::field`] names the protocol parameter so a boundary can answer `invalid_request` about it.

use crate::ErrorCategory;

/// A protocol value that does not have the shape its specification gives it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The value breaks the grammar of the parameter it was offered as.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// The protocol parameter, spelled as on the wire (`code_challenge`, `redirect_uri`, …).
        field: &'static str,
        /// Which rule the value broke.
        reason: &'static str,
    },
}

impl Error {
    /// The taxonomy category of this failure.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Invalid { .. } => ErrorCategory::Validation,
        }
    }

    /// The protocol parameter the failure is about.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::Invalid { field, .. } => field,
        }
    }
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
