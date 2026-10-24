//! `operator_grants` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One role held by one user; its record id is `<user id>.<role>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorGrantEntity {
    /// The holder.
    pub user_id: String,
    /// The role's name.
    pub role_name: String,
    /// Who gave it.
    pub granted_by: String,
    /// When, in Unix seconds.
    pub granted_at: i64,
    /// Why.
    pub reason: String,
    /// When it stops counting, in Unix seconds.
    pub expires_at: Option<i64>,
}

impl FromRecord for OperatorGrantEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            role_name: row.take("role_name")?,
            granted_by: row.take("granted_by")?,
            granted_at: row.take("granted_at")?,
            reason: row.take("reason")?,
            expires_at: row.take("expires_at")?,
        })
    }
}
