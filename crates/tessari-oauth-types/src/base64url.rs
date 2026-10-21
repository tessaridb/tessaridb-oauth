//! Unpadded base64url (RFC 4648 §5), the one encoding RFC 7636 and RFC 7638 put digests in.
//!
//! Written out rather than taken as a dependency: it is a few lines, it is pinned to the published RFC 7636 test
//! vector, and the alternative is a supply-chain surface for those few lines.

use tessari_oauth_constants::BASE64URL_ALPHABET;

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

/// Encode bytes as base64url with no padding.
pub(crate) fn encode(bytes: &[u8]) -> String {
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
