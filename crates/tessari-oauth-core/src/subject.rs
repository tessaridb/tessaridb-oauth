//! Pairwise subject identifiers (OpenID Connect Core §8.1): each client knows a user by an identifier of its own, so
//! two clients cannot join what they hold on the same person by comparing `sub`.
//!
//! The identifier is a keyed hash of the client and the user under a salt the server holds, so it is stable for the
//! pair, opaque to the client, and cannot be turned back into the user without the salt.

use ring::hmac;
use tessari_oauth_types::{ClientId, UserId, base64url};

/// The subject `sector` knows `user` by, under `salt`: base64url of HMAC-SHA-256 over the sector's length (eight
/// bytes, big-endian), the sector and the user — the length keeps the boundary between the two part of the input.
#[must_use]
pub fn pairwise(salt: &[u8], sector: &ClientId, user: &UserId) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut context = hmac::Context::with_key(&key);
    let sector = sector.as_str().as_bytes();
    // A length that does not fit in a u64 cannot occur; it saturates rather than wraps.
    let length = u64::try_from(sector.len()).unwrap_or(u64::MAX);
    context.update(&length.to_be_bytes());
    context.update(sector);
    context.update(user.as_str().as_bytes());
    base64url::encode(context.sign().as_ref())
}

#[cfg(test)]
#[path = "subject_tests.rs"]
mod tests;
