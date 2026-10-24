//! A client sector (OpenID Connect Core §8.1): clients registered under one sector are one product to the people who
//! use it, so each person has one pairwise subject across them instead of one per client. A name an operator types,
//! in the grammar a group name has.

use crate::group::{GRAMMAR, named};
use crate::{Error, Result};

/// A registered sector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sector(String);

impl Sector {
    /// Read a sector.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `sector` when the value is outside the grammar.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if !named(&raw) {
            return Err(Error::Invalid {
                field: "sector",
                reason: GRAMMAR,
            });
        }
        Ok(Self(raw))
    }

    /// The sector as registered.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "sector_tests.rs"]
mod tests;
