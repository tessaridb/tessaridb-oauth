//! Recovery codes: single-use codes that stand in for a lost second factor.
//!
//! Each code is 80 bits from the system random source, written as sixteen Crockford base32 characters in four groups,
//! an alphabet with no I, L, O or U so that a code read off paper is typed back right. The server keeps only a
//! SHA-256 digest: a code carries 80 bits, so a fast hash already makes it unguessable from the digest, and the code
//! is found by its digest as an identity. What the user types is read the way Crockford's alphabet reads — any case,
//! hyphens and spaces ignored, I and L as 1, O as 0.

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use tessari_oauth_constants::{RECOVERY_CODE_BYTES, RECOVERY_CODE_COUNT};
use tessari_oauth_types::base64url;

use crate::{Error, Result};

/// Crockford's base32 alphabet.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Characters in a code: five bits each.
const CODE_CHARS: usize = 16;

/// Characters in one shown group.
const GROUP_CHARS: usize = 4;

/// The sixteen characters of the 80 bits in `bytes`, five bits at a time from the top.
fn encode(bytes: &[u8; RECOVERY_CODE_BYTES]) -> String {
    let mut value = bytes.iter().fold(0_u128, |value, byte| {
        value.wrapping_shl(8) | u128::from(*byte)
    });
    let mut code = String::with_capacity(CODE_CHARS);
    for _ in 0..CODE_CHARS {
        // Bits 75..80 are the next five; what shifts above bit 80 is never read again.
        let index = usize::try_from(value.wrapping_shr(75) & 0x1f).unwrap_or(0);
        code.push(char::from(CROCKFORD.get(index).copied().unwrap_or(b'0')));
        value = value.wrapping_shl(5);
    }
    code
}

/// `code` split into groups of four joined by hyphens.
fn grouped(code: &str) -> String {
    code.as_bytes()
        .chunks(GROUP_CHARS)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// A fresh set of recovery codes, as the user is shown them once.
///
/// # Errors
///
/// [`Error::Custody`] when the system random source fails.
pub fn recovery_codes() -> Result<Vec<String>> {
    let random = SystemRandom::new();
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut bytes = [0_u8; RECOVERY_CODE_BYTES];
            random.fill(&mut bytes).map_err(|_| Error::Custody {
                reason: "the random source failed",
            })?;
            Ok(grouped(&encode(&bytes)))
        })
        .collect()
}

/// The digest a recovery code is stored and found under, or `None` when `code` is not one.
#[must_use]
pub fn recovery_digest(code: &str) -> Option<String> {
    let mut canonical = String::with_capacity(CODE_CHARS);
    for character in code
        .chars()
        .filter(|character| *character != '-' && *character != ' ')
    {
        let read = match character.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if !read.is_ascii() || !CROCKFORD.contains(&u8::try_from(read).ok()?) {
            return None;
        }
        canonical.push(read);
    }
    (canonical.len() == CODE_CHARS)
        .then(|| base64url::encode(digest(&SHA256, canonical.as_bytes()).as_ref()))
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
