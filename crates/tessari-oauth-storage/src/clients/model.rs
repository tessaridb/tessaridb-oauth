//! A client registration as it is handed in: its keys as the JWKs it registered, so they can be kept as given.

use std::collections::BTreeSet;

use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_types::{ClientId, RedirectUri, Resource, ScopeSet, Sector};

/// A client to register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewClient {
    /// The client's id, unique in its tenant.
    pub client_id: ClientId,
    /// Every redirect URI it may use.
    pub redirect_uris: Vec<RedirectUri>,
    /// The most a request from it may ever ask for.
    pub scope_ceiling: ScopeSet,
    /// The resources its tokens may be addressed to.
    pub resources: BTreeSet<Resource>,
    /// The one way it authenticates at the token endpoint.
    pub auth_method: AuthMethod,
    /// The grants it may redeem.
    pub grant_types: Vec<GrantType>,
    /// Its public signing keys as JWKs; required for `private_key_jwt`, empty otherwise.
    pub jwks: Vec<String>,
    /// Whether every access token issued to it must be bound to a DPoP key (RFC 9449 §5.2).
    pub dpop_bound_access_tokens: bool,
    /// Where a logout it asks for may send the browser.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// Where it is told that a session it holds ended.
    pub backchannel_logout_uri: Option<RedirectUri>,
    /// The sector it shares subjects under; none means its own.
    pub sector: Option<Sector>,
}
