//! The `passkeys` and `passkey_challenges` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One credential, under its id in base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyEntity {
    /// The user it belongs to.
    pub user_id: String,
    /// The COSE key as the authenticator sent it, base64url.
    pub public_key: String,
    /// The last signature counter the credential reported.
    pub sign_count: i64,
    /// Whether the credential may be synced to other devices.
    pub backup_eligible: bool,
    /// Unix seconds of the registration.
    pub created_at: i64,
}

impl FromRecord for PasskeyEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            public_key: row.take("public_key")?,
            sign_count: row.take("sign_count")?,
            backup_eligible: row.take("backup_eligible")?,
            created_at: row.take("created_at")?,
        })
    }
}

/// One issued challenge, under the challenge in base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeEntity {
    /// `create` for a registration, `get` for an assertion.
    pub ceremony: String,
    /// The user a registration challenge was issued to; none for a sign-in that has not named one.
    pub user_id: Option<String>,
    /// Unix seconds of the issue.
    pub created_at: i64,
}

impl FromRecord for ChallengeEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            ceremony: row.take("ceremony")?,
            user_id: row.take("user_id")?,
            created_at: row.take("created_at")?,
        })
    }
}
