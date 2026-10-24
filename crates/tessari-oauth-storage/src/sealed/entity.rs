//! One sealed value as its family's table stores it.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// A record's id as the node spells it, its sealed text, and the user it belongs to where the family keeps one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SealedEntity {
    pub(crate) spelled: String,
    /// Base64url, as every family writes it.
    pub(crate) sealed: String,
    pub(crate) user_id: Option<String>,
}

impl FromRecord for SealedEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            spelled: row.id().to_owned(),
            sealed: row.take("sealed")?,
            user_id: row.take("user_id")?,
        })
    }
}
