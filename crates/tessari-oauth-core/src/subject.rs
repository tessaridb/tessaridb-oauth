//! Pairwise subject identifiers (OpenID Connect Core §8.1): each client knows a user by an identifier of its own, so
//! two clients cannot join what they hold on the same person by comparing `sub`.
//!
//! The identifier is a keyed hash of the sector and the user under a salt the server holds, so it is stable for the
//! pair, opaque to the client, and cannot be turned back into the user without the salt. A client's sector is the
//! client itself unless it was registered under a named sector, which several clients of one product share.

use ring::hmac;
use tessari_oauth_types::{ClientId, Sector, UserId, base64url};

/// The one subject type this server issues (OpenID Connect Core §8).
pub const SUBJECT_TYPE_PAIRWISE: &str = "pairwise";

/// Marks a named sector's key. No client id holds it (ids are visible ASCII), so a sector can never be registered
/// under a name that joins the subjects some client already holds.
const NAMED_SECTOR_MARK: char = '\u{1}';

/// Whose subjects a client shares: its own, or those of the sector it was registered under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectSector {
    /// The client alone.
    Client(ClientId),
    /// Every client registered under this sector.
    Named(Sector),
}

impl SubjectSector {
    /// The key subjects are derived and recorded under: a client's id as written, a sector's name after the mark.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Client(client) => client.as_str().to_owned(),
            Self::Named(sector) => format!("{NAMED_SECTOR_MARK}{}", sector.as_str()),
        }
    }
}

/// The subject `sector` knows `user` by, under `salt`: base64url of HMAC-SHA-256 over the sector key's length (eight
/// bytes, big-endian), the key and the user — the length keeps the boundary between the two part of the input.
#[must_use]
pub fn pairwise(salt: &[u8], sector: &SubjectSector, user: &UserId) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut context = hmac::Context::with_key(&key);
    let sector = sector.key();
    let sector = sector.as_bytes();
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
