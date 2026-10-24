//! A company's groups and the roles a group carries.
//!
//! Both are names an operator types and a client reads in a claim, so they share one narrow grammar: lowercase, so
//! `Staff` and `staff` cannot be two groups, and starting with a letter or digit. Two types rather than strings so a
//! role cannot be passed where a group was meant, nor either where a user was.

use tessari_oauth_constants::GROUP_NAME_MAX_LEN;

use crate::{Error, Result};

/// What either name must be, as a refusal says it.
const GRAMMAR: &str =
    "1 to 64 lowercase letters, digits, hyphens and underscores, starting with a letter or digit";

/// Whether `raw` is inside the grammar both names share.
fn named(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let within_length = (1..=GROUP_NAME_MAX_LEN).contains(&bytes.len());
    let first = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let alphabet = bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-' || *byte == b'_'
    });
    within_length && first && alphabet
}

/// A group of a company: 1 to 64 lowercase letters, digits, hyphens and underscores.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(String);

impl GroupId {
    /// Read a group id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `group` when the value is outside the grammar.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if !named(&raw) {
            return Err(Error::Invalid {
                field: "group",
                reason: GRAMMAR,
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

/// A role a group carries, released to clients as a label; never an operator's role.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupRole(String);

impl GroupRole {
    /// Read a role name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `role` when the value is outside the grammar.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if !named(&raw) {
            return Err(Error::Invalid {
                field: "role",
                reason: GRAMMAR,
            });
        }
        Ok(Self(raw))
    }

    /// The name as stored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "group_tests.rs"]
mod tests;
