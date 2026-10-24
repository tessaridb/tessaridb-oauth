//! The user a code, a consent or a session belongs to, inside one tenant.
//!
//! The id is the account's own stable identifier, assigned by the server and never an email address or a name: an
//! address changes hands and a name is not unique, and a grant attached to either follows the string rather than
//! the person. A type rather than a string so that a user id cannot be passed where a client or tenant id was meant.

use tessari_oauth_constants::USER_ID_MAX_LEN;

use crate::{Error, Result};

/// A user's id: 1 to 64 ASCII letters, digits, hyphens and underscores.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(String);

impl UserId {
    /// Read a user id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `user` when the value is empty, longer than 64 bytes, or holds anything but
    /// ASCII letters, digits, `-` and `_`.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        let bytes = raw.as_bytes();
        let within_length = (1..=USER_ID_MAX_LEN).contains(&bytes.len());
        let alphabet = bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_');
        if !(within_length && alphabet) {
            return Err(Error::Invalid {
                field: "user",
                reason: "1 to 64 letters, digits, hyphens and underscores",
            });
        }
        Ok(Self(raw))
    }

    /// The id as stored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "user_id_tests.rs"]
mod tests;
