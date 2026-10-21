//! `refresh_families` and `refresh_tokens` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One family; its record id is the digest of the family's first token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyEntity {
    /// The tenant the family lives in.
    pub tenant: String,
    /// The client the family belongs to.
    pub client_id: String,
    /// The user its tokens act for.
    pub user_id: String,
    /// Unix seconds of the family's first token.
    pub created_at: i64,
    /// Unix seconds after which no token of the family rotates, however recently used.
    pub expires_at: i64,
    /// Unix seconds of the revocation; absent while the family stands.
    pub revoked_at: Option<i64>,
    /// Why it was revoked.
    pub revoked_reason: Option<String>,
}

/// One token of a family; its record id is the token's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenEntity {
    /// The family it belongs to.
    pub family_id: String,
    /// The tenant the family lives in.
    pub tenant: String,
    /// The client that may present it.
    pub client_id: String,
    /// The user it acts for.
    pub user_id: String,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// The resources the scopes were granted at.
    pub resources: Vec<String>,
    /// Unix seconds after which the token no longer rotates if unused.
    pub idle_expires_at: i64,
    /// Unix seconds of its rotation; absent while unspent.
    pub rotated_at: Option<i64>,
}

impl FromRecord for FamilyEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            tenant: row.take("tenant")?,
            client_id: row.take("client_id")?,
            user_id: row.take("user_id")?,
            created_at: row.take("created_at")?,
            expires_at: row.take("expires_at")?,
            revoked_at: row.take("revoked_at")?,
            revoked_reason: row.take("revoked_reason")?,
        })
    }
}

impl FromRecord for TokenEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            family_id: row.take("family_id")?,
            tenant: row.take("tenant")?,
            client_id: row.take("client_id")?,
            user_id: row.take("user_id")?,
            scopes: row.take("scopes")?,
            resources: row.take("resources")?,
            idle_expires_at: row.take("idle_expires_at")?,
            rotated_at: row.take("rotated_at")?,
        })
    }
}
