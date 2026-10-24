//! A service credential's id: the name an operator gives a program that calls the company's admin API without a
//! console session, in the grammar a group name has.

use crate::group::{GRAMMAR, named};
use crate::{Error, Result};

/// A registered service.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceId(String);

impl ServiceId {
    /// Read a service id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `service` when the value is outside the grammar.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        if !named(&raw) {
            return Err(Error::Invalid {
                field: "service",
                reason: GRAMMAR,
            });
        }
        Ok(Self(raw))
    }

    /// The id as registered.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "service_id_tests.rs"]
mod tests;
