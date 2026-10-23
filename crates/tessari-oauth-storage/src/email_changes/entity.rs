//! `email_changes` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One requested change; its record id is the digest of the token that confirms it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailChangeEntity {
    /// The record id as the node spelled it.
    pub spelled: String,
    /// The account whose address changes.
    pub user_id: String,
    /// The address the account signed in with when the change was asked for.
    pub old_address: String,
    /// The address it changes to.
    pub new_address: String,
    /// The digest of the token that cancels the change.
    pub cancel_digest: String,
    /// When the change was asked for, in Unix seconds.
    pub created_at: i64,
    /// When the new address confirmed it, in Unix seconds.
    pub confirmed_at: Option<i64>,
}

impl FromRecord for EmailChangeEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            spelled: row.id().to_owned(),
            user_id: row.take("user_id")?,
            old_address: row.take("old_address")?,
            new_address: row.take("new_address")?,
            cancel_digest: row.take("cancel_digest")?,
            created_at: row.take("created_at")?,
            confirmed_at: row.take("confirmed_at")?,
        })
    }
}
