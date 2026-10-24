//! The value a browser holds in its sign-in cookie, binding a sign-in in progress to that browser.
//!
//! The server keeps only its digest, as the record's identity: a request from another browser carries another value
//! and finds no record at all. The type never prints its value, so a log line that formats it shows a placeholder.

use std::fmt;

use sha2::Digest as _;

use crate::base64url;

/// A sign-in cookie's value. Only [`SigninBinding::digest`] leaves this type; the value never does by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct SigninBinding(String);

impl SigninBinding {
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

impl fmt::Debug for SigninBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigninBinding(<redacted>)")
    }
}

#[cfg(test)]
#[path = "signin_binding_tests.rs"]
mod tests;
