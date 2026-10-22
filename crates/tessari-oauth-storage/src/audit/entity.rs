//! `audit` messages exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row, Value};

/// One message's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntity {
    /// The kind's name.
    pub kind: String,
    /// The client id.
    pub client_id: Option<String>,
    /// The user id.
    pub user_id: Option<String>,
    /// The token's `sub`.
    pub subject: Option<String>,
    /// The scopes.
    pub scopes: Option<Vec<String>>,
    /// The audience.
    pub audience: Option<String>,
    /// The token's `jti`.
    pub jti: Option<String>,
    /// The client authentication method.
    pub auth_method: Option<String>,
    /// The bound key's thumbprint.
    pub jkt: Option<String>,
    /// The reason.
    pub reason: Option<String>,
    /// A cascade's family count.
    pub families: Option<i64>,
    /// Who acted.
    pub actor: Option<String>,
    /// The operator role's name.
    pub role_name: Option<String>,
    /// Unix seconds of the event.
    pub at: i64,
}

impl FromRecord for AuditEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            kind: row.take("kind")?,
            client_id: row.take("client_id")?,
            user_id: row.take("user_id")?,
            subject: row.take("subject")?,
            scopes: row.take("scopes")?,
            audience: row.take("audience")?,
            jti: row.take("jti")?,
            auth_method: row.take("auth_method")?,
            jkt: row.take("jkt")?,
            reason: row.take("reason")?,
            families: row.take("families")?,
            actor: row.take("actor")?,
            role_name: row.take("role_name")?,
            at: row.take("at")?,
        })
    }
}

/// One message as a topic read answers it: its position and its value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AuditMessageEntity {
    /// The record id, as spelled.
    pub(crate) id: String,
    /// The message's position.
    pub(crate) position: i64,
    /// The message's value.
    pub(crate) value: Value,
}

impl FromRecord for AuditMessageEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            id: row.id().to_owned(),
            position: row.take("position")?,
            value: row.take("value")?,
        })
    }
}
