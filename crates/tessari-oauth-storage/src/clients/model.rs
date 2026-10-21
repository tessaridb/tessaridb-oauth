//! A client registration as it is handed in: its keys as the JWKs it registered, so they can be kept as given.

use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_types::{ClientId, RedirectUri, ScopeSet};

/// A client to register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewClient {
    /// The client's id, unique in its tenant.
    pub client_id: ClientId,
    /// Every redirect URI it may use.
    pub redirect_uris: Vec<RedirectUri>,
    /// The most a request from it may ever ask for.
    pub scope_ceiling: ScopeSet,
    /// The one way it authenticates at the token endpoint.
    pub auth_method: AuthMethod,
    /// The grants it may redeem.
    pub grant_types: Vec<GrantType>,
    /// Its public signing keys as JWKs; required for `private_key_jwt`, empty otherwise.
    pub jwks: Vec<String>,
    /// Whether every access token issued to it must be bound to a DPoP key (RFC 9449 §5.2).
    pub dpop_bound_access_tokens: bool,
}
