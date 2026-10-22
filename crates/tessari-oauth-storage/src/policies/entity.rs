//! The `two_factor` row exactly as stored, under the id `policy`.

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
