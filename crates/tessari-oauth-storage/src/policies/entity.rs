//! The `two_factor` and `registration` rows exactly as stored, each under the id `policy`.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// A company's two-factor policy as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntity {
    /// `off`, `optional` or `required`; the table refuses anything else.
    pub policy: String,
}

impl FromRecord for PolicyEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            policy: row.take("policy")?,
        })
    }
}

/// The `registration` row exactly as stored, under the id `policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationEntity {
    /// Whether people may open their own account.
    pub open: bool,
    /// The domains an address must belong to; none means any.
    pub domains: Vec<String>,
    /// Counts the changes; the first kept policy is 1.
    pub revision: i64,
}

impl FromRecord for RegistrationEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            open: row.take("open")?,
            domains: row.take("domains")?,
            revision: row.take("revision")?,
        })
    }
}
