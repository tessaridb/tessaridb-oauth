//! Password hashing: Argon2id (RFC 9106) over an HMAC-SHA-256 of the password under a pepper read from a file.
//!
//! The pepper lives outside the database, so a dump of the stored hashes alone cannot be attacked offline. The
//! password is put in Normalization Form C before anything else (NIST SP 800-63B-4 §3.1.1.2), so the same characters
//! typed on two keyboards are one password. Every hash and every check runs on the blocking pool, a bounded number at
//! a time: each one holds the configured memory, and the bound is what keeps a burst of sign-ins from holding more.

use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use tessari_oauth_constants::{
    PASSWORD_HASH_ITERATIONS_FLOOR, PASSWORD_HASH_MEMORY_KIB_FLOOR, PASSWORD_HASH_OUTPUT_BYTES,
    PASSWORD_HASH_PARALLELISM_FLOOR, PASSWORD_SALT_BYTES, PEPPER_MIN_BYTES,
};
use tokio::sync::Semaphore;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Permission bits that let anyone but the owner reach the file.
const OTHERS_MASK: u32 = 0o077;

/// What the dummy hash is made of; nothing is ever compared against it as a real password.
const DUMMY_PASSWORD: &str = "no account has this password";

/// The Argon2id cost every new hash is made at; never below the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordCost {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl PasswordCost {
    /// A cost of `memory_kib` KiB, `iterations` passes and `parallelism` lanes.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for `password_hash_cost` when any of the three is below its floor.
    pub const fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        if memory_kib < PASSWORD_HASH_MEMORY_KIB_FLOOR
            || iterations < PASSWORD_HASH_ITERATIONS_FLOOR
            || parallelism < PASSWORD_HASH_PARALLELISM_FLOOR
        {
            return Err(Error::InvalidConfig {
                field: "password_hash_cost",
                reason: "below the floor of 65536 KiB, 3 iterations and 1 lane",
            });
        }
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// Whether a hash made with `params` was made below this cost.
    fn exceeds(&self, params: &Params) -> bool {
        params.m_cost() < self.memory_kib
            || params.t_cost() < self.iterations
            || params.p_cost() < self.parallelism
    }
}

/// What a presented password proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// It is the account's password; `rehash` asks for it to be stored again at the current cost.
    Match {
        /// The stored hash was made at a lower cost than the current one.
        rehash: bool,
    },
    /// It is not, or there is no account.
    Mismatch,
}

/// The pepper and the cost; hashing and verifying run off the request workers, a bounded number at a time.
pub struct Passwords {
    pepper: hmac::Key,
    cost: PasswordCost,
    random: SystemRandom,
    /// A hash at the current cost that an unknown account is checked against, so it costs what a known one does.
    dummy: String,
    gate: Semaphore,
}

impl fmt::Debug for Passwords {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Passwords")
            .field("cost", &self.cost)
            .finish_non_exhaustive()
    }
}

fn refuse(reason: &'static str) -> Error {
    Error::InvalidConfig {
        field: "password_pepper",
        reason,
    }
}

const fn custody(reason: &'static str) -> Error {
    Error::Custody { reason }
}

impl Passwords {
    /// Read the pepper from `pepper_path` — at least 32 bytes in a file only its owner can read — and prepare
    /// hashing at `cost`, at most `concurrency` at a time. Called once at startup: it reads a file and makes one hash.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for `password_pepper` when the file cannot be read, any group or other permission bit
    /// is set, or it holds fewer than 32 bytes; [`Error::Custody`] when the dummy hash cannot be made.
    pub fn load(pepper_path: &Path, cost: PasswordCost, concurrency: usize) -> Result<Arc<Self>> {
        let metadata =
            std::fs::metadata(pepper_path).map_err(|_| refuse("the file cannot be read"))?;
        if metadata.permissions().mode() & OTHERS_MASK != 0 {
            return Err(refuse(
                "readable by group or others; it must be mode 600 or 400",
            ));
        }
        let bytes = Zeroizing::new(
            std::fs::read(pepper_path).map_err(|_| refuse("the file cannot be read"))?,
        );
        if bytes.len() < PEPPER_MIN_BYTES {
            return Err(refuse("it must hold at least 32 bytes"));
        }
        let mut passwords = Self {
            pepper: hmac::Key::new(hmac::HMAC_SHA256, &bytes),
            cost,
            random: SystemRandom::new(),
            dummy: String::new(),
            gate: Semaphore::new(concurrency.max(1)),
        };
        passwords.dummy = passwords.hash_now(DUMMY_PASSWORD)?;
        Ok(Arc::new(passwords))
    }

    /// `password` hashed for storage, as a PHC string.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] when the random source or the hash fails.
    pub async fn hash(self: &Arc<Self>, password: &str) -> Result<String> {
        let password = Zeroizing::new(password.to_owned());
        self.off_workers(move |passwords| passwords.hash_now(&password))
            .await
    }

    /// Whether `password` matches `stored`; `None` is an unknown account, checked against the dummy hash so it costs
    /// the same, and never a match.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] when `stored` is not an Argon2id PHC string or the hash fails.
    pub async fn verify(self: &Arc<Self>, password: &str, stored: Option<&str>) -> Result<Verdict> {
        let password = Zeroizing::new(password.to_owned());
        let stored = stored.map(str::to_owned);
        self.off_workers(move |passwords| match &stored {
            Some(stored) => passwords.verify_now(&password, stored),
            None => passwords
                .verify_now(&password, &passwords.dummy)
                .map(|_| Verdict::Mismatch),
        })
        .await
    }

    /// Run `work` on the blocking pool once a permit is free; the permit is held until it finishes.
    async fn off_workers<T, F>(self: &Arc<Self>, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Self) -> Result<T> + Send + 'static,
    {
        let _permit = self
            .gate
            .acquire()
            .await
            .map_err(|_| custody("the password gate closed"))?;
        let passwords = Arc::clone(self);
        tokio::task::spawn_blocking(move || work(&passwords))
            .await
            .map_err(|_| custody("the password task did not finish"))?
    }

    /// The pepper's HMAC of `password` in Normalization Form C: what Argon2id is handed instead of the password.
    fn peppered(&self, password: &str) -> Zeroizing<Vec<u8>> {
        let normalised = Zeroizing::new(password.nfc().collect::<String>());
        Zeroizing::new(
            hmac::sign(&self.pepper, normalised.as_bytes())
                .as_ref()
                .to_vec(),
        )
    }

    fn hash_now(&self, password: &str) -> Result<String> {
        let mut salt = [0_u8; PASSWORD_SALT_BYTES];
        self.random
            .fill(&mut salt)
            .map_err(|_| custody("the random source failed"))?;
        let salt = SaltString::encode_b64(&salt).map_err(|_| custody("the salt did not encode"))?;
        let params = Params::new(
            self.cost.memory_kib,
            self.cost.iterations,
            self.cost.parallelism,
            Some(PASSWORD_HASH_OUTPUT_BYTES),
        )
        .map_err(|_| custody("the hash parameters are not usable"))?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password(&self.peppered(password), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| custody("hashing failed"))
    }

    fn verify_now(&self, password: &str, stored: &str) -> Result<Verdict> {
        let not_ours = || custody("a stored password hash that is not an Argon2id PHC string");
        let parsed = PasswordHash::new(stored).map_err(|_| not_ours())?;
        if Algorithm::try_from(parsed.algorithm) != Ok(Algorithm::Argon2id) {
            return Err(not_ours());
        }
        let params = Params::try_from(&parsed).map_err(|_| not_ours())?;
        let version = parsed
            .version
            .map_or(Ok(Version::V0x13), Version::try_from)
            .map_err(|_| not_ours())?;
        let rehash = version != Version::V0x13 || self.cost.exceeds(&params);
        // The library compares the derived tag with the stored one in constant time.
        match Argon2::new(Algorithm::Argon2id, version, params)
            .verify_password(&self.peppered(password), &parsed)
        {
            Ok(()) => Ok(Verdict::Match { rehash }),
            Err(argon2::password_hash::Error::Password) => Ok(Verdict::Mismatch),
            Err(_) => Err(custody("verifying failed")),
        }
    }
}

#[cfg(test)]
#[path = "passwords_tests.rs"]
mod tests;
