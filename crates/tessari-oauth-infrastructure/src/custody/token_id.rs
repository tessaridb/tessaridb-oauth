//! Random values this server makes: identifiers for the tokens it signs, and secrets it keeps sealed.

use ring::rand::{SecureRandom, SystemRandom};
use tessari_oauth_types::base64url;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Random bytes in a token id: 128 bits, so two tokens never share one by chance.
const TOKEN_ID_BYTES: usize = 16;

/// Random bytes in a kept secret: 256 bits.
const SECRET_BYTES: usize = 32;

/// A fresh 256-bit secret from the system's cryptographic random source, cleared when dropped.
///
/// # Errors
///
/// [`Error::Custody`] when the random source fails.
pub fn random_secret() -> Result<Zeroizing<Vec<u8>>> {
    let mut secret = Zeroizing::new(vec![0_u8; SECRET_BYTES]);
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| Error::Custody {
            reason: "the random source failed",
        })?;
    Ok(secret)
}

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
