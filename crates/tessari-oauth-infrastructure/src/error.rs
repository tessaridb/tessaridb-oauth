//! Failures of `tessari-oauth-infrastructure`.
//!
//! Three things can go wrong talking to the store and they call for three different answers: the store could not
//! be reached (try later), the store answered no (its words, verbatim, with the class it gave), or a name handed to
//! this crate was not a name (a defect in the caller).

use tessari_oauth_types::ErrorCategory;
use tessaridb_client::RefusalClass;

/// A failure reaching or using the store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The store could not be reached or the connection broke.
    #[error("the store is unavailable: {message}")]
    Unavailable {
        /// What the transport reported.
        message: String,
    },
    /// The store refused the statement.
    #[error("{message}")]
    Refused {
        /// The node's own words.
        message: String,
        /// What the node says to do about it; `None` from a node too old to send one.
        class: Option<RefusalClass>,
    },
    /// A store configuration this crate will not run with.
    #[error("{field}: {reason}")]
    InvalidConfig {
        /// The setting at fault.
        field: &'static str,
        /// What it must be instead.
        reason: &'static str,
    },
    /// Key custody could not seal, open, generate or use a key; the reason names the step, never the material.
    #[error("key custody: {reason}")]
    Custody {
        /// Which step failed.
        reason: &'static str,
    },
    /// A required configuration variable is not set.
    #[error("{key} is required")]
    Unset {
        /// The variable.
        key: &'static str,
    },
    /// A configuration variable holds a value that does not fit; secrets are never parsed, so never carried here.
    #[error("{key}={value:?}: expected {reason}")]
    Invalid {
        /// The variable.
        key: &'static str,
        /// The value read.
        value: String,
        /// What it must be.
        reason: &'static str,
    },
    /// A mail could not be built or the relay did not take it; the reason never carries the mail's text.
    #[error("mail: {reason}")]
    Mail {
        /// What failed.
        reason: String,
    },
    /// A namespace or database name that is not a plain name.
    #[error("not a plain name: {name:?}")]
    InvalidName {
        /// The value offered as a name.
        name: String,
    },
}

impl Error {
    /// Whether the store refused with the class that says asking again can succeed. `conflict` shares the
    /// category with it and means the opposite — the state must change first — so the two are told apart here.
    #[must_use]
    pub const fn is_retry(&self) -> bool {
        matches!(
            self,
            Self::Refused {
                class: Some(RefusalClass::Retry),
                ..
            }
        )
    }

    /// The taxonomy category of this failure.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Unavailable { .. } | Self::Mail { .. } => ErrorCategory::Unavailable,
            Self::Refused {
                class: Some(RefusalClass::Retry | RefusalClass::Conflict),
                ..
            } => ErrorCategory::Conflict,
            Self::Refused {
                class: Some(RefusalClass::Unauthenticated),
                ..
            } => ErrorCategory::Unauthorized,
            Self::Refused {
                class: Some(RefusalClass::Forbidden),
                ..
            } => ErrorCategory::Forbidden,
            Self::Refused {
                class: Some(RefusalClass::Throttled | RefusalClass::Unavailable),
                ..
            } => ErrorCategory::Unavailable,
            Self::Unset { .. } | Self::Invalid { .. } => ErrorCategory::Validation,
            Self::Refused { .. }
            | Self::InvalidName { .. }
            | Self::InvalidConfig { .. }
            | Self::Custody { .. } => ErrorCategory::Internal,
        }
    }
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
