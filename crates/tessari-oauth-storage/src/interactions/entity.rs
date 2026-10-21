//! `interactions` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One pending authorization; its record id is random.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractionEntity {
    /// The tenant the request was made to.
    pub tenant: String,
    /// The client that asked.
    pub client_id: String,
    /// The redirect URI the code will be delivered to.
    pub redirect_uri: String,
    /// The scopes requested.
    pub scopes: Vec<String>,
    /// The PKCE challenge.
    pub challenge: String,
    /// The client's `state`.
    pub state: Option<String>,
    /// The resources the code will grant.
    pub resources: Vec<String>,
    /// The client's `nonce`.
    pub nonce: Option<String>,
    /// Whether the client asked that no page be shown.
    pub silent: bool,
    /// Unix seconds of the request.
    pub created_at: i64,
    /// Unix seconds the browser brought it — absent while a pushed request waits for its browser.
    pub claimed_at: Option<i64>,
}

impl FromRecord for InteractionEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            tenant: row.take("tenant")?,
            client_id: row.take("client_id")?,
            redirect_uri: row.take("redirect_uri")?,
            scopes: row.take("scopes")?,
            challenge: row.take("challenge")?,
            state: row.take("state")?,
            resources: row.take("resources")?,
            nonce: row.take("nonce")?,
            silent: row.take("silent")?,
            created_at: row.take("created_at")?,
            claimed_at: row.take("claimed_at")?,
        })
    }
}
