//! The `Idempotency-Key` an operator's change carries, so that a change sent twice is made once.
//!
//! A key is the operator's own: the record a change is kept under is named by the operator and the key together, so
//! two operators who chose the same key never meet.

use sha2::Digest as _;
use tessari_oauth_constants::{IDEMPOTENCY_KEY_MAX_LEN, IDEMPOTENCY_KEY_MIN_LEN};

use crate::{Actor, Error, Result, base64url};

/// An idempotency key: 16 to 128 characters of `A-Z`, `a-z`, `0-9`, `-` and `_`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Read a key as the request header carries it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `idempotency_key` when the value is shorter than 16 or longer than 128
    /// characters, or holds anything but letters, digits, `-` and `_`.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        let within_length =
            (IDEMPOTENCY_KEY_MIN_LEN..=IDEMPOTENCY_KEY_MAX_LEN).contains(&raw.len());
        let alphabet = raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if !(within_length && alphabet) {
            return Err(Error::Invalid {
                field: "idempotency_key",
                reason: "16 to 128 letters, digits, '-' or '_'",
            });
        }
        Ok(Self(raw))
    }

    /// The identity of the record `actor`'s change under this key is kept under: unpadded base64url of the SHA-256
    /// of the actor's name, a line break and the key.
    #[must_use]
    pub fn record_id(&self, actor: &Actor) -> String {
        let named = format!("{}\n{}", actor.name(), self.0);
        base64url::encode(&sha2::Sha256::digest(named.as_bytes()))
    }
}

/// The digest a request's body is remembered by, so a key sent again with another body is told apart: unpadded
/// base64url of its SHA-256.
#[must_use]
pub fn request_digest(body: &[u8]) -> String {
    base64url::encode(&sha2::Sha256::digest(body))
}

#[cfg(test)]
#[path = "idempotency_key_tests.rs"]
mod tests;
