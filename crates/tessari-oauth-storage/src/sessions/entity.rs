//! `sessions` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One session; its record id is the digest of the browser's session cookie value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEntity {
    /// The account signed in.
    pub user_id: String,
    /// The session's public id, which logout names it by; drawn at sign-in, never the cookie or its digest.
    pub sid: String,
    /// The methods verified when it signed in, by name, in order.
    pub methods: Vec<String>,
    /// Unix seconds of the sign-in.
    pub auth_time: i64,
    /// Unix seconds the session was last found by a request.
    pub seen_at: i64,
}

impl FromRecord for SessionEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            sid: row.take("sid")?,
            methods: row.take("methods")?,
            auth_time: row.take("auth_time")?,
            seen_at: row.take("seen_at")?,
        })
    }
}
