//! A `codes` row exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One issued code's row; its record id is the code's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeEntity {
    /// The tenant whose issuer minted the code.
    pub tenant: String,
    /// The client the code was issued to.
    pub client_id: String,
    /// The redirect URI exactly as the authorization request named it.
    pub redirect_uri: String,
    /// The PKCE S256 challenge.
    pub challenge: String,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// Unix seconds after which the code no longer redeems.
    pub expires_at: i64,
    /// Unix seconds of the redemption; absent while the code is unspent.
    pub redeemed_at: Option<i64>,
}

impl FromRecord for CodeEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            tenant: row.take("tenant")?,
            client_id: row.take("client_id")?,
            redirect_uri: row.take("redirect_uri")?,
            challenge: row.take("challenge")?,
            scopes: row.take("scopes")?,
            expires_at: row.take("expires_at")?,
            redeemed_at: row.take("redeemed_at")?,
        })
    }
}
