//! Failures of `tessari-oauth-storage`.

use tessari_oauth_types::ErrorCategory;

/// A failure storing or reading a protocol record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The store could not be reached, or refused in a way this crate does not interpret.
    #[error(transparent)]
    Store(#[from] tessari_oauth_infrastructure::Error),
    /// A record handed in breaks a rule of its kind; nothing was written.
    #[error("an invalid {record}: {reason}")]
    Invalid {
        /// The kind of record.
        record: &'static str,
        /// The rule it breaks.
        reason: &'static str,
    },
    /// A stored record does not have the shape this crate writes; nothing can currently judge it.
    #[error("a stored {record} is unreadable: {reason}")]
    Unreadable {
        /// The kind of record.
        record: &'static str,
        /// What did not fit.
        reason: String,
    },
}

impl Error {
    /// The taxonomy category of this failure.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Store(store) => store.category(),
            Self::Invalid { .. } => ErrorCategory::Validation,
            Self::Unreadable { .. } => ErrorCategory::Internal,
        }
    }
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
