//! The key a token is bound to, named by its JWK thumbprint (RFC 7638).
//!
//! A DPoP-bound token (RFC 9449) records the thumbprint of the client's public key, and every later use of the
//! token must come with a proof signed by that key. The thumbprint is a SHA-256 digest in unpadded base64url, so
//! it is always 43 characters. A type rather than a string, because a thumbprint and the token it binds are both
//! base64url text, and a binding compared against the wrong one of the two matches nothing and reads like a client
//! with the wrong key.

use sha2::Digest as _;
use tessari_oauth_constants::SHA256_BASE64URL_LEN;

use crate::{Error, Result, base64url};

/// The RFC 7638 thumbprint of the public key a token is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyThumbprint(String);

impl KeyThumbprint {
    /// Read a thumbprint as written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `jkt` when it is not 43 base64url characters without padding: anything else
    /// is not a SHA-256 thumbprint and could never name a key.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if raw.len() != SHA256_BASE64URL_LEN || !base64url::is_alphabet(&raw) {
            return Err(Error::Invalid {
                field: "jkt",
                reason: "a key thumbprint is 43 base64url characters, unpadded",
            });
        }
        Ok(Self(raw))
    }

    /// The thumbprint of a key given as its RFC 7638 canonical JSON: the required members only, in lexicographic
    /// order, with no whitespace. Building that form is the caller's part; hashing it is this one.
    #[must_use]
    pub fn of_canonical_jwk(canonical: &str) -> Self {
        Self(base64url::encode(&sha2::Sha256::digest(
            canonical.as_bytes(),
        )))
    }

    /// The thumbprint as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "thumbprint_tests.rs"]
mod tests;
