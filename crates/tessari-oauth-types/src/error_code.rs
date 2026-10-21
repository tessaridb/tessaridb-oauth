//! The `error` values an OAuth response may carry (RFC 6749 §4.1.2.1 and §5.2).
//!
//! Only these strings ever reach a client; the precise reason for a refusal goes to the audit log instead, so the
//! answer cannot become an oracle about which check failed.

/// An `error` value of an authorization or token error response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The request is missing a parameter, repeats one, or is otherwise malformed.
    InvalidRequest,
    /// The authorization server does not support this `response_type`.
    UnsupportedResponseType,
    /// The requested scope is unknown, malformed or beyond what the client may request.
    InvalidScope,
    /// Client authentication failed.
    InvalidClient,
    /// The authorization grant is invalid, expired, revoked or was issued to another client or URI.
    InvalidGrant,
    /// The authorization server does not support this `grant_type`.
    UnsupportedGrantType,
}

impl ErrorCode {
    /// The value as written on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
        }
    }
}

#[cfg(test)]
#[path = "error_code_tests.rs"]
mod tests;
