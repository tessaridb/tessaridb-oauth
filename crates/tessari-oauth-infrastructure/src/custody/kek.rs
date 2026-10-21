//! The key-encryption key and the sealing it does (ChaCha20-Poly1305, RFC 8439).

use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use tessari_oauth_types::TenantId;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Permission bits that let anyone but the owner reach the file.
const OTHERS_MASK: u32 = 0o077;

/// The key every tenant's signing keys are sealed under. Its bytes never leave this type.
pub struct Kek {
    key: LessSafeKey,
    random: SystemRandom,
}

impl fmt::Debug for Kek {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Kek(..)")
    }
}

fn refuse(reason: &'static str) -> Error {
    Error::InvalidConfig {
        field: "key_encryption_key",
        reason,
    }
}

const fn custody(reason: &'static str) -> Error {
    Error::Custody { reason }
}

/// What a sealed key is bound to: its tenant and its `kid`, so it cannot be moved onto another row and opened there.
fn binding(tenant: &TenantId, kid: &str) -> Vec<u8> {
    format!("{}\0{kid}", tenant.as_str()).into_bytes()
}

impl Kek {
    /// Read the key from `path`: exactly 32 bytes, in a file only its owner can read. Read once at startup, before
    /// the server serves, so the blocking read never runs on a request.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for `key_encryption_key` when the file cannot be read, any group or other permission
    /// bit is set, or it does not hold exactly 32 bytes.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path).map_err(|_| refuse("the file cannot be read"))?;
        if metadata.permissions().mode() & OTHERS_MASK != 0 {
            return Err(refuse(
                "readable by group or others; it must be mode 600 or 400",
            ));
        }
        let bytes =
            Zeroizing::new(std::fs::read(path).map_err(|_| refuse("the file cannot be read"))?);
        // The cipher takes exactly a 32-byte key and refuses any other length.
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &bytes)
            .map_err(|_| refuse("it must hold exactly 32 bytes"))?;
        Ok(Self {
            key: LessSafeKey::new(unbound),
            random: SystemRandom::new(),
        })
    }

    /// Seal `plaintext` for `tenant` and `kid`: a fresh random nonce, then the ciphertext with its tag.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] when the system random source or the cipher fails.
    pub fn seal(&self, tenant: &TenantId, kid: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0_u8; NONCE_LEN];
        self.random
            .fill(&mut nonce)
            .map_err(|_| custody("the random source failed"))?;
        let mut sealed = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(binding(tenant, kid)),
                &mut sealed,
            )
            .map_err(|_| custody("sealing failed"))?;
        let mut framed = nonce.to_vec();
        framed.extend(sealed);
        Ok(framed)
    }

    /// Open what [`Kek::seal`] sealed for `tenant` and `kid`.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] when the input is shorter than a nonce, or it was sealed under another key, for another
    /// tenant or `kid`, or altered.
    pub fn unseal(
        &self,
        tenant: &TenantId,
        kid: &str,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (nonce, ciphertext) = sealed
            .split_first_chunk::<NONCE_LEN>()
            .ok_or(custody("a sealed key shorter than its nonce"))?;
        let mut opened = Zeroizing::new(ciphertext.to_vec());
        let plaintext_len = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(binding(tenant, kid)),
                &mut opened,
            )
            .map_err(|_| custody("a sealed key that does not open here"))?
            .len();
        opened.truncate(plaintext_len);
        Ok(opened)
    }
}

#[cfg(test)]
#[path = "kek_tests.rs"]
mod tests;
