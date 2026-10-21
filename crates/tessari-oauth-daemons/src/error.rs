//! Failures of `tessari-oauth-daemons`: a run that did not complete, named by its daemon.

use tessari_oauth_types::ErrorCategory;

/// A failure of this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A run of `daemon` failed; `message` says where, without secret material.
    #[error("daemon {daemon} failed: {message}")]
    Run {
        /// The daemon's name.
        daemon: &'static str,
        /// What failed.
        message: String,
        /// The category of the underlying failure.
        category: ErrorCategory,
    },
}

impl Error {
    /// The taxonomy category of this failure.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Run { category, .. } => *category,
        }
    }
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
