//! Failures of `tessari-oauth-observability`.

/// A failure setting up observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The process already has a subscriber; a second one would never receive an event.
    #[error("a tracing subscriber is already installed")]
    AlreadyInstalled,
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
