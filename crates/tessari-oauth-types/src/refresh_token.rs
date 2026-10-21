//! A refresh token as the server holds it between minting and storing, and as it is presented back (RFC 6749 §6).
//!
//! A refresh token carries a session, so the server keeps only its digest: a leaked table of digests refreshes
//! nothing. A type of its own rather than a string or an authorization code, so that one can never be passed where
//! the other was meant, and one that never prints its value.

use std::fmt;

use sha2::Digest as _;

use crate::base64url;

/// A refresh token. Only [`RefreshToken::digest`] leaves this type; the value never does by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshToken(String);

impl RefreshToken {
    /// Wrap a token as minted or as presented at the token endpoint.
    #[must_use]
    pub fn from_secret(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The token's storage identity: unpadded base64url of its SHA-256.
    #[must_use]
    pub fn digest(&self) -> String {
        base64url::encode(&sha2::Sha256::digest(self.0.as_bytes()))
    }

    /// The token itself, for the one place it must leave: the token response.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RefreshToken(<redacted>)")
    }
}

#[cfg(test)]
#[path = "refresh_token_tests.rs"]
mod tests;
