//! The names a sign-in's failures are counted under: keyed digests, so the counters hold no address and no password,
//! and a copy of them cannot be checked against a list of addresses without the pepper.
//!
//! The key is derived from the password pepper (HKDF-SHA-256, RFC 5869) under a label of its own, so it is never the
//! key the passwords are peppered with. Each part is written with its length before it, so no two lists of parts
//! digest alike. A password is put in Normalization Form C first, as it is for hashing.

use std::fmt;

use ring::{hkdf, hmac};
use tessari_oauth_types::base64url;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// What the derivation is labelled with.
const LABEL: &[u8] = b"tessaridb-oauth sign-in keys";

/// The key the sign-in counters are named under.
pub struct SigninKeys {
    key: hmac::Key,
}

impl fmt::Debug for SigninKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SigninKeys").finish_non_exhaustive()
    }
}

/// The output length the derived key is expanded to, in bytes: one SHA-256 block.
struct KeyLength;

impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

impl SigninKeys {
    /// The key derived from `pepper`.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] when the derivation fails.
    pub(super) fn from_pepper(pepper: &[u8]) -> Result<Self> {
        let mut derived = Zeroizing::new([0_u8; 32]);
        hkdf::Salt::new(hkdf::HKDF_SHA256, &[])
            .extract(pepper)
            .expand(&[LABEL], KeyLength)
            .and_then(|okm| okm.fill(derived.as_mut_slice()))
            .map_err(|_| Error::Custody {
                reason: "the sign-in key could not be derived",
            })?;
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, derived.as_slice()),
        })
    }

    /// The account key of `email` in `tenant`: the same for every attempt at that address, known or not.
    #[must_use]
    pub fn account(&self, tenant: &str, email: &str) -> String {
        self.digest(&[b"account", tenant.as_bytes(), email.as_bytes()])
    }

    /// The credential-pair key of `email` and `password` in `tenant`.
    #[must_use]
    pub fn pair(&self, tenant: &str, email: &str, password: &str) -> String {
        let normalised = Zeroizing::new(password.nfc().collect::<String>());
        self.digest(&[
            b"pair",
            tenant.as_bytes(),
            email.as_bytes(),
            normalised.as_bytes(),
        ])
    }

    /// The keyed digest of `parts`, each preceded by its length, base64url.
    fn digest(&self, parts: &[&[u8]]) -> String {
        let mut context = hmac::Context::with_key(&self.key);
        for part in parts {
            let length = u64::try_from(part.len()).unwrap_or(u64::MAX);
            context.update(&length.to_be_bytes());
            context.update(part);
        }
        base64url::encode(context.sign().as_ref())
    }
}

#[cfg(test)]
#[path = "signin_keys_tests.rs"]
mod tests;
