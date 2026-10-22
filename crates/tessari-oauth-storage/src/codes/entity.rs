//! A `codes` row exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One issued code's row; its record id is the code's digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeEntity {
    /// The tenant whose issuer minted the code.
    pub tenant: String,
    /// The client the code was issued to.
    pub client_id: String,
    /// The user who authorised the code.
    pub user_id: String,
    /// The redirect URI exactly as the authorization request named it.
    pub redirect_uri: String,
    /// The PKCE S256 challenge.
    pub challenge: String,
    /// The granted scopes.
    pub scopes: Vec<String>,
    /// The resources the scopes were granted at.
    pub resources: Vec<String>,
    /// Unix seconds after which the code no longer redeems.
    pub expires_at: i64,
    /// Unix seconds of the user's sign-in.
    pub auth_time: i64,
    /// The methods the sign-in verified, by name, in order.
    pub methods: Vec<String>,
    /// The public id of the session the sign-in opened.
    pub sid: String,
    /// The authorization request's `nonce`, when it carried one.
    pub nonce: Option<String>,
    /// Unix seconds of the redemption; absent while the code is unspent.
    pub redeemed_at: Option<i64>,
}

impl FromRecord for CodeEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            tenant: row.take("tenant")?,
            client_id: row.take("client_id")?,
            user_id: row.take("user_id")?,
            redirect_uri: row.take("redirect_uri")?,
            challenge: row.take("challenge")?,
            scopes: row.take("scopes")?,
            resources: row.take("resources")?,
            expires_at: row.take("expires_at")?,
            auth_time: row.take("auth_time")?,
            methods: row.take("methods")?,
            sid: row.take("sid")?,
            nonce: row.take("nonce")?,
            redeemed_at: row.take("redeemed_at")?,
        })
    }
}
