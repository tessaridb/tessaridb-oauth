//! A `secrets` row exactly as stored: one sealed secret of the tenant under the id naming its purpose.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One sealed secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEntity {
    /// The secret sealed under the key-encryption key, base64url.
    pub sealed: String,
    /// Unix seconds of its making.
    pub created_at: i64,
}

impl FromRecord for SecretEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            sealed: row.take("sealed")?,
            created_at: row.take("created_at")?,
        })
    }
}

/// A `pairwise_subjects` row exactly as stored: whom one derived subject stands for, under the subject itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectEntity {
    /// The client the subject was derived for.
    pub client_id: String,
    /// The user it stands for.
    pub user_id: String,
}

impl FromRecord for SubjectEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            client_id: row.take("client_id")?,
            user_id: row.take("user_id")?,
        })
    }
}
