//! An email address as a sign-in identifier and as the key its account is found by.
//!
//! The address is kept lowercased whole. The local part is case-sensitive in RFC 5321, but no provider a user signs
//! in with treats it so, and two accounts differing only by case would let whoever registers the second variant pass
//! for the owner of the first. The check is the shape every deliverable address has — a local part, one `@`, a domain
//! of at least two non-empty labels, no space or control character, within SMTP's lengths — and no more: whether an
//! address delivers is decided by verifying it, never by parsing it.

use tessari_oauth_constants::{EMAIL_LOCAL_MAX_LEN, EMAIL_MAX_LEN};

use crate::{Error, Result};

/// An email address in the form it is kept and compared in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Read an email address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `email` when the value is empty or longer than 254 bytes, does not hold exactly
    /// one `@`, has a local part empty or longer than 64 bytes, a domain without a dot or with an empty label, or any
    /// whitespace or control character.
    pub fn parse(raw: &str) -> Result<Self> {
        let refused = Error::Invalid {
            field: "email",
            reason: "an address of a local part, one @ and a domain with a dot, without spaces",
        };
        // Judged as kept: lowercasing may lengthen a character, and the kept form is what must fit.
        let kept = raw.to_lowercase();
        if kept.len() > EMAIL_MAX_LEN
            || kept
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(refused);
        }
        let Some((local, domain)) = kept.split_once('@') else {
            return Err(refused);
        };
        let local_fits = (1..=EMAIL_LOCAL_MAX_LEN).contains(&local.len());
        let domain_fits = domain.contains('.') && domain.split('.').all(|label| !label.is_empty());
        if !local_fits || !domain_fits || domain.contains('@') {
            return Err(refused);
        }
        Ok(Self(kept))
    }

    /// The address as kept.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "email_tests.rs"]
mod tests;
