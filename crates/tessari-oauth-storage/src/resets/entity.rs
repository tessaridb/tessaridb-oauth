//! `password_resets` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One live reset token; its record id is the token's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetEntity {
    /// The account the token resets.
    pub user_id: String,
    /// When it was issued, in Unix seconds.
    pub created_at: i64,
}

impl FromRecord for ResetEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            created_at: row.take("created_at")?,
        })
    }
}
