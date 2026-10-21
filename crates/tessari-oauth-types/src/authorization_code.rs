//! An authorization code as the server holds it for the moment between minting and storing (RFC 6749 §4.1.2).
//!
//! A code is a bearer secret that crosses the browser, so the server keeps only its digest: a leaked table of
//! digests redeems nothing, because redemption needs the code itself. The type never prints its value, so a log
//! line or an error that formats it shows a placeholder instead.

use std::fmt;

use sha2::Digest as _;

use crate::base64url;

/// An authorization code. Only [`AuthorizationCode::digest`] leaves this type; the value never does by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationCode(String);

impl AuthorizationCode {
    /// Wrap a code as minted or as presented at the token endpoint.
    #[must_use]
    pub fn from_secret(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The code's storage identity: unpadded base64url of its SHA-256.
    #[must_use]
    pub fn digest(&self) -> String {
        base64url::encode(&sha2::Sha256::digest(self.0.as_bytes()))
    }

    /// The code itself, for the one place it must leave: the redirect back to the client.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuthorizationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationCode(<redacted>)")
    }
}

#[cfg(test)]
#[path = "authorization_code_tests.rs"]
mod tests;
