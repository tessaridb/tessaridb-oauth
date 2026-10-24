//! The one-time token an address-verification mail carries in its link.
//!
//! It proves that whoever opened the link reads the address it was sent to, so the server keeps only its digest, as
//! the record's identity. The type never prints its value, so a log line that formats it shows a placeholder.

use std::fmt;

use sha2::Digest as _;

use crate::base64url;

/// An address-verification token. Only [`VerifyToken::digest`] leaves this type unless it is exposed on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyToken(String);

impl VerifyToken {
    /// Wrap a value as minted or as presented.
    #[must_use]
    pub fn from_secret(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The value's storage identity: unpadded base64url of its SHA-256.
    #[must_use]
    pub fn digest(&self) -> String {
        base64url::encode(&sha2::Sha256::digest(self.0.as_bytes()))
    }

    /// The value itself, for the one place it must leave: the link in the mail.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VerifyToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifyToken(<redacted>)")
    }
}

#[cfg(test)]
#[path = "verify_token_tests.rs"]
mod tests;
