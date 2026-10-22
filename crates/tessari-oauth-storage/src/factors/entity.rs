//! The `totp_factors` row exactly as stored, under the user's id.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One user's time-based one-time code factor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpEntity {
    /// The user's id.
    pub user_id: String,
    /// The shared secret sealed under the key-encryption key, base64url.
    pub sealed: String,
    /// The last time step a code was accepted for; 0 before the first.
    pub last_step: i64,
    /// Unix seconds of the enrolment.
    pub created_at: i64,
}

impl FromRecord for TotpEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            sealed: row.take("sealed")?,
            last_step: row.take("last_step")?,
            created_at: row.take("created_at")?,
        })
    }
}

/// A `recovery_codes` row, under the code's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeEntity {
    /// The user it belongs to.
    pub(crate) user_id: String,
}

impl FromRecord for CodeEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
        })
    }
}

/// A one-time code secret a session is enrolling, under the session's public id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingTotpEntity {
    /// The user enrolling it.
    pub(crate) user_id: String,
    /// The secret, sealed, base64url.
    pub(crate) sealed: String,
    /// Unix seconds it was drawn.
    pub(crate) created_at: i64,
}

impl FromRecord for PendingTotpEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            sealed: row.take("sealed")?,
            created_at: row.take("created_at")?,
        })
    }
}
