//! `admin_signins`, `admin_sessions` and `admin_actions` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// A sign-in to the admin console in progress; its record id is the digest of the browser's sign-in cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSigninEntity {
    /// The digest of the `state` sent to the issuer.
    pub state: String,
    /// The PKCE verifier the code will be redeemed with.
    pub verifier: String,
    /// The `nonce` the code must carry back.
    pub nonce: String,
    /// When it began, in Unix seconds.
    pub created_at: i64,
}

impl FromRecord for PendingSigninEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            state: row.take("state")?,
            verifier: row.take("verifier")?,
            nonce: row.take("nonce")?,
            created_at: row.take("created_at")?,
        })
    }
}

/// An admin console session; its record id is the digest of the console's session cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSessionEntity {
    /// The operator signed in.
    pub user_id: String,
    /// The public id of the issuer session the sign-in came from.
    pub sid: String,
    /// The methods the sign-in verified, by name, in order.
    pub methods: Vec<String>,
    /// When the sign-in happened, in Unix seconds.
    pub auth_time: i64,
    /// When a request last found it, in Unix seconds.
    pub seen_at: i64,
}

impl FromRecord for AdminSessionEntity {
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

/// An operator's change kept under its idempotency key for a day; its record id names the operator and the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminActionEntity {
    /// The operator who sent it.
    pub operator: String,
    /// The change, by name.
    pub action: String,
    /// The digest of the request it was sent with.
    pub request: String,
    /// The status it was answered with, once it was made.
    pub status: Option<i64>,
    /// The body it was answered with, once it was made.
    pub answer: Option<String>,
    /// When it was claimed, in Unix seconds.
    pub created_at: i64,
}

impl FromRecord for AdminActionEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            operator: row.take("operator")?,
            action: row.take("action")?,
            request: row.take("request")?,
            status: row.take("status")?,
            answer: row.take("answer")?,
            created_at: row.take("created_at")?,
        })
    }
}
