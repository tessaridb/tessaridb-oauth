//! Where a unit of work runs: a namespace and a database, checked before they become statement text.
//!
//! A value is bound and can never become syntax; a NAME is grammar and has to be written into the script. So the
//! two names are checked against a pattern narrower than the node's own lexer, and a string that is not a name is
//! refused rather than quoted into acceptance.

use crate::{Error, Result};

/// A namespace and a database, both proven to be plain names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Place {
    namespace: String,
    database: String,
}

/// Whether `name` is `[A-Za-z_][A-Za-z0-9_]*` and at most 64 bytes.
fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let starts = bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_');
    starts && name.len() <= 64 && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

impl Place {
    /// A place from two names.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] naming the first that is not a plain name.
    pub fn new(namespace: impl Into<String>, database: impl Into<String>) -> Result<Self> {
        let namespace = namespace.into();
        let database = database.into();
        for name in [&namespace, &database] {
            if !is_name(name) {
                return Err(Error::InvalidName { name: name.clone() });
            }
        }
        Ok(Self {
            namespace,
            database,
        })
    }

    /// The namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The database.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    /// The statements that select this place, sent ahead of every unit of work: a pooled connection that
    /// reconnected has forgotten any earlier `USE`, and reading the wrong database is not an error.
    #[must_use]
    pub fn preamble(&self) -> String {
        format!(
            "USE NAMESPACE {}; USE DATABASE {};",
            self.namespace, self.database
        )
    }
}

#[cfg(test)]
#[path = "place_tests.rs"]
mod tests;
