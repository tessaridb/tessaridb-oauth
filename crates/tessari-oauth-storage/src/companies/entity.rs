//! `companies` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One company; its record id is the company's tenant id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyEntity {
    /// The name people see.
    pub name: String,
    /// `provisioning`, `active` or `suspended`.
    pub status: String,
    /// When it was created, in Unix seconds.
    pub created_at: i64,
    /// Who created it: an operator's user id, or `configuration` for a company the server's settings name.
    pub created_by: String,
}

impl FromRecord for CompanyEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            name: row.take("name")?,
            status: row.take("status")?,
            created_at: row.take("created_at")?,
            created_by: row.take("created_by")?,
        })
    }
}

/// One listed company: the record id as the node spells it, and the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedEntity {
    pub(crate) spelled: String,
    pub(crate) company: CompanyEntity,
}

impl FromRecord for ListedEntity {
    fn from_row(row: Row) -> Result<Self, MappingFault> {
        let spelled = row.id().to_owned();
        Ok(Self {
            spelled,
            company: CompanyEntity::from_row(row)?,
        })
    }
}
