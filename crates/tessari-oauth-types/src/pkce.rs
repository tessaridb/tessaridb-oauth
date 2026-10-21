//! Proof that the client redeeming a code is the client that asked for it (RFC 7636).
//!
//! The authorization code travels through a place neither end controls — a redirect, which is a URL, which reaches
//! the browser's history, the operating system's URL handler, a proxy log and whatever listens on a loopback port.
//! A code alone is therefore a bearer secret lying in the open for as long as it lives, and PKCE is what makes
//! possessing it insufficient: the client sends only the digest of its `code_verifier` when it asks for the code,
//! and the verifier itself when it redeems. Whoever stole the code has the digest at most, and a digest does not
//! reverse.
//!
//! # S256, and nothing else
//!
//! `plain` sends the verifier as the challenge, which protects nothing once the authorization request is
//! observable — and the authorization request is the observable thing. It is not implemented, there is no field to
//! record which method a code used, and a request naming `plain` is refused by the caller rather than honoured.
//!
//! # Why a type rather than two functions
//!
//! So that the comparison cannot be written the wrong way round or with `==`. A [`Challenge`] is built from what
//! the client sent and asked with [`Challenge::matches`] about what the client presents; there is no way to spell
//! the reverse and no way to reach the bytes and compare them carelessly.

use sha2::Digest as _;
use subtle::ConstantTimeEq as _;
use tessari_oauth_constants::{PKCE_VERIFIER_MAX_LEN, PKCE_VERIFIER_MIN_LEN, SHA256_BASE64URL_LEN};

use crate::{Error, Result, base64url};

/// Whether a byte is in the `unreserved` set RFC 7636 §4.1 restricts a verifier to.
const fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// Whether a verifier is inside RFC 7636 §4.1's grammar: its length bounds and the unreserved set.
fn well_formed(verifier: &str) -> bool {
    (PKCE_VERIFIER_MIN_LEN..=PKCE_VERIFIER_MAX_LEN).contains(&verifier.len())
        && verifier.bytes().all(unreserved)
}

/// The S256 transform: base64url of the SHA-256 of the verifier's ASCII bytes (RFC 7636 §4.2).
fn digest(verifier: &str) -> String {
    base64url::encode(&sha2::Sha256::digest(verifier.as_bytes()))
}

/// What a client sent when it asked for a code: the base64url SHA-256 of its verifier.
///
/// Carried as the text the client sent rather than as decoded bytes. Nothing ever needs the bytes — the only
/// question asked is whether the verifier presented now produces this same string — and a decoder is a second
/// place to be wrong about padding, alphabet and length on a path a stranger reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge(String);

impl Challenge {
    /// Read a challenge as the client sent it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `code_challenge` when it is not 43 base64url characters without padding: a
    /// challenge of another shape was produced by something that is not SHA-256, and the honest answer is a
    /// refusal rather than a comparison that never matches and reads like a wrong verifier.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        // 32 bytes of digest are exactly 43 characters, so the length is an equality and not a range.
        if raw.len() != SHA256_BASE64URL_LEN {
            return Err(Error::Invalid {
                field: "code_challenge",
                reason: "an S256 challenge is 43 base64url characters",
            });
        }
        if !base64url::is_alphabet(&raw) {
            return Err(Error::Invalid {
                field: "code_challenge",
                reason: "it holds a character outside the base64url alphabet, or padding",
            });
        }
        Ok(Self(raw))
    }

    /// The challenge a verifier produces — the client's half of the same transform.
    ///
    /// Here rather than in a client so that the two sides cannot hold two implementations of the one thing they
    /// must agree about.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `code_verifier` when the verifier is outside RFC 7636's grammar: shorter
    /// than 43 characters, longer than 128, or holding a character outside the unreserved set. A short verifier
    /// hashes perfectly well and protects nothing, and the only moment to refuse it is before the code is asked
    /// for.
    pub fn of(verifier: &str) -> Result<Self> {
        if !well_formed(verifier) {
            return Err(Error::Invalid {
                field: "code_verifier",
                reason: "a verifier is 43 to 128 characters of the unreserved set",
            });
        }
        Ok(Self(digest(verifier)))
    }

    /// Whether `verifier` is the one this challenge was made from.
    ///
    /// The verifier's grammar is checked here rather than by the caller: a caller who forgets leaves the length
    /// floor unenforced, and an unenforced floor accepts a three-character verifier while every test passes.
    #[must_use]
    pub fn matches(&self, verifier: &str) -> bool {
        if !well_formed(verifier) {
            return false;
        }
        // Constant time, as every comparison of a protocol value in this workspace is. The challenge is public and
        // this leaks nothing either way; the rule is uniform so that no reviewer has to notice an exception.
        digest(verifier).as_bytes().ct_eq(self.0.as_bytes()).into()
    }

    /// The challenge as the client sent it, for writing into the code's record.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "pkce_tests.rs"]
mod tests;
