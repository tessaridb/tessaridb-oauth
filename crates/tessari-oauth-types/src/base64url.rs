//! Unpadded base64url (RFC 4648 §5), the one encoding RFC 7636 and RFC 7638 put digests in and JOSE puts every
//! segment in.
//!
//! Written out rather than taken as a dependency: it is a few lines, it is pinned to the published RFC 4648 test
//! vectors, and the alternative is a supply-chain surface for those few lines. Decoding is strict — no padding and
//! no stray low bits — so every byte string has exactly one accepted spelling.

use tessari_oauth_constants::BASE64URL_ALPHABET;

use crate::{Error, Result};

/// The refusal for text that is not canonical unpadded base64url.
const NOT_BASE64URL: Error = Error::Invalid {
    field: "base64url",
    reason: "unpadded base64url with no bits beyond the encoded bytes",
};

/// Whether every byte of `text` is a base64url character; padding is not one.
pub(crate) fn is_alphabet(text: &str) -> bool {
    text.bytes().all(|byte| BASE64URL_ALPHABET.contains(&byte))
}

/// One six-bit group as its base64url character.
///
/// The mask is applied here rather than trusted from the caller, which makes the function total. The fallback is
/// unreachable by the mask; it is `=` rather than a plausible letter so that a change breaking the invariant
/// produces a character base64url never contains, and fails a comparison loudly.
fn character(six_bits: u8) -> char {
    let slot = usize::from(six_bits & 0b0011_1111);
    char::from(*BASE64URL_ALPHABET.get(slot).unwrap_or(&b'='))
}

/// The six-bit value of one base64url character.
fn value(character: u8) -> Result<u8> {
    BASE64URL_ALPHABET
        .iter()
        .position(|candidate| *candidate == character)
        .and_then(|slot| u8::try_from(slot).ok())
        .ok_or(NOT_BASE64URL)
}

/// Decode unpadded base64url.
///
/// # Errors
///
/// Returns [`Error::Invalid`] for `base64url` on padding or any other character outside the alphabet, on a length
/// that cannot end a group (one character over a multiple of four), and on a final character carrying bits beyond
/// the encoded bytes.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let mut decoded = Vec::with_capacity(text.len().saturating_mul(3).div_ceil(4));
    for group in text.as_bytes().chunks(4) {
        let mut values = [0_u8; 4];
        for (slot, character) in values.iter_mut().zip(group) {
            *slot = value(*character)?;
        }
        let [first, second, third, fourth] = values;
        let bytes = [
            (first << 2) | (second >> 4),
            (second << 4) | (third >> 2),
            (third << 6) | fourth,
        ];
        let (count, stray) = match group.len() {
            2 => (1, second & 0b0000_1111),
            3 => (2, third & 0b0000_0011),
            4 => (3, 0),
            _ => return Err(NOT_BASE64URL),
        };
        if stray != 0 {
            return Err(NOT_BASE64URL);
        }
        decoded.extend(bytes.iter().take(count));
    }
    Ok(decoded)
}

/// Encode bytes as base64url with no padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(4).div_ceil(3));
    for group in bytes.chunks(3) {
        let first = group.first().copied().unwrap_or(0);
        let second = group.get(1).copied().unwrap_or(0);
        let third = group.get(2).copied().unwrap_or(0);
        encoded.push(character(first >> 2));
        encoded.push(character((first << 4) | (second >> 4)));
        // No padding: a group short of three bytes emits the characters its bits reach and stops.
        if group.len() > 1 {
            encoded.push(character((second << 2) | (third >> 6)));
        }
        if group.len() > 2 {
            encoded.push(character(third));
        }
    }
    encoded
}

#[cfg(test)]
#[path = "base64url_tests.rs"]
mod tests;
