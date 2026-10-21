//! Identifiers for tokens this server signs.

use ring::rand::{SecureRandom, SystemRandom};
use tessari_oauth_types::base64url;

use crate::{Error, Result};

/// Random bytes in a token id: 128 bits, so two tokens never share one by chance.
const TOKEN_ID_BYTES: usize = 16;

/// A fresh token id (`jti`) from the system's cryptographic random source, base64url without padding.
///
/// # Errors
///
/// [`Error::Custody`] when the random source fails.
pub fn token_id() -> Result<String> {
    let mut bytes = [0_u8; TOKEN_ID_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Custody {
            reason: "the random source failed",
        })?;
    Ok(base64url::encode(&bytes))
}

#[cfg(test)]
#[path = "token_id_tests.rs"]
mod tests;
