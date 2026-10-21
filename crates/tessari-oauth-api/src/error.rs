//! Failures of `tessari-oauth-api`, and how each is answered: a status and a stable `code` with a fixed message,
//! never the inner error's text, which may name hosts, tables or records.

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_types::ErrorCategory;

/// A failure of this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The path names nothing this server serves — an unknown tenant included.
    #[error("not found")]
    NotFound,
    /// The store did not answer.
    #[error("the store did not answer")]
    Store(#[source] tessari_oauth_storage::Error),
    /// A stored value could not be turned into the answer: a defect, not the caller's.
    #[error("an answer could not be built")]
    Internal,
    /// The client made more requests than its limit allows in this window.
    #[error("too many requests")]
    Throttled {
        /// Seconds until the window ends.
        retry_after_secs: u64,
    },
}

impl Error {
    /// The taxonomy category of this failure.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::NotFound => ErrorCategory::NotFound,
            Self::Store(store) => store.category(),
            Self::Internal => ErrorCategory::Internal,
            Self::Throttled { .. } => ErrorCategory::Throttled,
        }
    }
}

/// The body of every refusal.
#[derive(Serialize)]
struct Body {
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if let Self::Throttled { retry_after_secs } = self {
            // RFC 9110 §10.2.3: the wait in whole seconds.
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after_secs.to_string())],
                Json(Body {
                    code: "rate_limited",
                    message: "too many requests; try again after the stated wait",
                }),
            )
                .into_response();
        }
        let (status, code, message) = match self.category() {
            ErrorCategory::NotFound => {
                (StatusCode::NOT_FOUND, "not_found", "nothing is served here")
            }
            ErrorCategory::Unavailable | ErrorCategory::Timeout => (
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "try again later",
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "the server could not answer",
            ),
        };
        if status.is_server_error() {
            tracing::error!(error = %self, source = ?std::error::Error::source(&self), "a request failed");
        }
        (status, Json(Body { code, message })).into_response()
    }
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;
