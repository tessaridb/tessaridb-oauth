//! The `users`, `user_emails` and `credentials` rows exactly as stored; each record id is also kept as a field,
//! because the store answers a string id in its quoted form.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntity {
    /// The account's id, random and never reused.
    pub user_id: String,
    /// The tenant it belongs to.
    pub tenant: String,
    /// `active` or `disabled`.
    pub status: String,
    /// Unix seconds of its registration.
    pub created_at: i64,
}

/// An account's profile names as stored on its `users` row, each absent until set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileEntity {
    /// The full name.
    pub name: Option<String>,
    /// The given name.
    pub given_name: Option<String>,
    /// The family name.
    pub family_name: Option<String>,
}

/// The email address an account signs in with, under the address in its kept form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailEntity {
    /// The address, lowercased.
    pub address: String,
    /// The account it belongs to.
    pub user_id: String,
    /// Unix seconds of its verification, absent until it is verified.
    pub verified_at: Option<i64>,
    /// How it was verified.
    pub verified_by: Option<String>,
}

/// An account's password credential, under the account's id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialEntity {
    /// The account's id.
    pub user_id: String,
    /// The password hash as a PHC string.
    pub hash: String,
    /// The version of the pepper it was hashed under.
    pub pepper: i64,
    /// Unix seconds of the last change.
    pub updated_at: i64,
}

impl FromRecord for UserEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            tenant: row.take("tenant")?,
            status: row.take("status")?,
            created_at: row.take("created_at")?,
        })
    }
}

impl FromRecord for EmailEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            address: row.take("address")?,
            user_id: row.take("user_id")?,
            verified_at: row.take("verified_at")?,
            verified_by: row.take("verified_by")?,
        })
    }
}

impl FromRecord for CredentialEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            user_id: row.take("user_id")?,
            hash: row.take("hash")?,
            pepper: row.take("pepper")?,
            updated_at: row.take("updated_at")?,
        })
    }
}

impl FromRecord for ProfileEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            name: row.take("name")?,
            given_name: row.take("given_name")?,
            family_name: row.take("family_name")?,
        })
    }
}
