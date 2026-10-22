//! A `clients` row exactly as stored; its record id is the client id, also kept as a field because the store
//! answers a string id in its quoted form.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One client's registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEntity {
    /// The tenant it is registered in.
    pub tenant: String,
    /// The client id.
    pub client_id: String,
    /// Its registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// The most it may ever ask for.
    pub scope_ceiling: Vec<String>,
    /// The resources its tokens may be addressed to.
    pub resources: Vec<String>,
    /// Its token-endpoint authentication method, by registry name.
    pub auth_method: String,
    /// The assertion algorithm, for `private_key_jwt` only.
    pub assertion_alg: Option<String>,
    /// The grants it may redeem, by `grant_type` name.
    pub grant_types: Vec<String>,
    /// Its public keys, each a JWK as registered.
    pub jwks: Vec<String>,
    /// Whether every access token issued to it must be DPoP-bound.
    pub dpop_bound_access_tokens: bool,
    /// Unix seconds of the registration.
    pub registered_at: i64,
    /// Its post-logout redirect URIs; absent on a client registered before they were kept.
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

impl FromRecord for ClientEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            client_id: row.take("client_id")?,
            tenant: row.take("tenant")?,
            redirect_uris: row.take("redirect_uris")?,
            scope_ceiling: row.take("scope_ceiling")?,
            resources: row.take("resources")?,
            auth_method: row.take("auth_method")?,
            assertion_alg: row.take("assertion_alg")?,
            grant_types: row.take("grant_types")?,
            jwks: row.take("jwks")?,
            dpop_bound_access_tokens: row.take("dpop_bound_access_tokens")?,
            registered_at: row.take("registered_at")?,
            post_logout_redirect_uris: row.take("post_logout_redirect_uris")?,
        })
    }
}
