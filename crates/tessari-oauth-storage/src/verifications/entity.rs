//! `address_verifications` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One live verification token; its record id is the token's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationEntity {
    /// The account the token was sent for.
    pub user_id: String,
    /// The address it was sent to.
    pub address: String,
    /// When it was issued, in Unix seconds.
    pub created_at: i64,
}

impl FromRecord for VerificationEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            address: row.take("address")?,
            created_at: row.take("created_at")?,
        })
    }
}
