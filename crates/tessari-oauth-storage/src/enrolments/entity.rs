//! `enrolments` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One live enrolment code; its record id is the code's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentEntity {
    /// The account the code enrols.
    pub user_id: String,
    /// When it was issued, in Unix seconds.
    pub created_at: i64,
    /// The operator who issued it.
    pub created_by: String,
}

impl FromRecord for EnrolmentEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            created_at: row.take("created_at")?,
            created_by: row.take("created_by")?,
        })
    }
}
