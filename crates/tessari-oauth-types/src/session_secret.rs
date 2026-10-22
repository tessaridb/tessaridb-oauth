//! The value a browser holds in its session cookie once its user has signed in at this issuer.
//!
//! It is the user's session at the authorization server, so the server keeps only its digest, as the record's
//! identity: a stolen copy of the sessions table opens no session. The type never prints its value, so a log line
//! that formats it shows a placeholder.

use std::fmt;

use sha2::Digest as _;

use crate::base64url;

/// A session cookie's value. Only [`SessionSecret::digest`] leaves this type; the value never does by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionSecret(String);

impl SessionSecret {
    /// Wrap a value as minted or as presented in the cookie.
    #[must_use]
    pub fn from_secret(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The value's storage identity: unpadded base64url of its SHA-256.
    #[must_use]
    pub fn digest(&self) -> String {
        base64url::encode(&sha2::Sha256::digest(self.0.as_bytes()))
    }

    /// The value itself, for the one place it must leave: the cookie set on the browser.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionSecret(<redacted>)")
    }
}

#[cfg(test)]
#[path = "session_secret_tests.rs"]
mod tests;
