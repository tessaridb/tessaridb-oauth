//! A `consents` row exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One user's grant to one client; its record id is the user id, a space, and the client id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEntity {
    /// The tenant the grant lives in.
    pub tenant: String,
    /// The user who granted it.
    pub user_id: String,
    /// The client it was granted to.
    pub client_id: String,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// The resources the scopes were granted at.
    pub resources: Vec<String>,
    /// The consent policy version the user was shown.
    pub policy_version: i64,
    /// The version of the descriptions the user was shown.
    pub shown_version: String,
    /// Unix seconds of the last grant or widening.
    pub granted_at: i64,
    /// Counts the writes; a write is accepted only over the revision it read.
    pub revision: i64,
    /// Unix seconds of the revocation; absent while the grant stands.
    pub revoked_at: Option<i64>,
    /// Who or what revoked it.
    pub revoked_by: Option<String>,
}

impl FromRecord for ConsentEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            tenant: row.take("tenant")?,
            user_id: row.take("user_id")?,
            client_id: row.take("client_id")?,
            scopes: row.take("scopes")?,
            resources: row.take("resources")?,
            policy_version: row.take("policy_version")?,
            shown_version: row.take("shown_version")?,
            granted_at: row.take("granted_at")?,
            revision: row.take("revision")?,
            revoked_at: row.take("revoked_at")?,
            revoked_by: row.take("revoked_by")?,
        })
    }
}
