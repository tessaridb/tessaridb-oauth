//! `groups` and `group_members` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One group; its record id is the group id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntity {
    /// The group id.
    pub group_id: String,
    /// The company it belongs to.
    pub tenant: String,
    /// What it is for, as an operator wrote it.
    pub description: String,
    /// The roles its members are released as.
    pub roles: Vec<String>,
    /// When it was made, in Unix seconds.
    pub created_at: i64,
}

impl FromRecord for GroupEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            group_id: row.take("group_id")?,
            tenant: row.take("tenant")?,
            description: row.take("description")?,
            roles: row.take("roles")?,
            created_at: row.take("created_at")?,
        })
    }
}

/// One user in one group; its record id is `<group id>.<user id>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEntity {
    /// The group.
    pub group_id: String,
    /// The member.
    pub user_id: String,
    /// When they were added, in Unix seconds.
    pub added_at: i64,
    /// Who added them.
    pub added_by: String,
}

impl FromRecord for MembershipEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            group_id: row.take("group_id")?,
            user_id: row.take("user_id")?,
            added_at: row.take("added_at")?,
            added_by: row.take("added_by")?,
        })
    }
}
