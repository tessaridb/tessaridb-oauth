//! The registration envelope of one client — the blast radius of that client, as data (oauth client policy).

use std::collections::BTreeSet;

use tessari_oauth_types::{ClientId, RedirectUri, Resource, ScopeSet, TenantId};

use crate::jose::{Algorithm, VerifyingKey};

/// How a client authenticates at the token endpoint. Exactly one is pinned per client; a request using another
/// method is refused even when that other method would be acceptable, so a client cannot be downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// A public client: it presents its `client_id` and nothing else, and is always held to PKCE.
    None,
    /// A client secret in the `Authorization` header (`client_secret_basic`).
    ClientSecretBasic,
    /// A client secret in the request body (`client_secret_post`).
    ClientSecretPost,
    /// An assertion signed with one of the client's registered keys under this algorithm (`private_key_jwt`).
    PrivateKeyJwt(Algorithm),
}

impl AuthMethod {
    /// The method's name in the OAuth registry, as `token_endpoint_auth_method` writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt(_) => "private_key_jwt",
        }
    }
}

/// A grant the token endpoint redeems. A client redeems only the ones it registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantType {
    /// `authorization_code` (RFC 6749 §4.1.3).
    AuthorizationCode,
    /// `refresh_token` (RFC 6749 §6).
    RefreshToken,
}

impl GrantType {
    /// Every grant the token endpoint redeems; the one list both the endpoint and the metadata read.
    pub const ALL: [Self; 2] = [Self::AuthorizationCode, Self::RefreshToken];

    /// The grant's `grant_type` value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// What a client is allowed to do, registered in one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistration {
    /// The tenant the client is registered in.
    pub tenant: TenantId,
    /// The client's id.
    pub client_id: ClientId,
    /// Every redirect URI the client registered.
    pub redirect_uris: Vec<RedirectUri>,
    /// The most a request from this client may ever ask for.
    pub scope_ceiling: ScopeSet,
    /// The resources its tokens may be addressed to.
    pub resources: BTreeSet<Resource>,
    /// The one way this client authenticates at the token endpoint.
    pub auth_method: AuthMethod,
    /// The grants this client may redeem at the token endpoint.
    pub grant_types: Vec<GrantType>,
    /// The public keys the client signs its assertions with; empty unless it authenticates by `private_key_jwt`.
    pub keys: Vec<VerifyingKey>,
    /// Whether every access token issued to this client must be bound to a DPoP key (RFC 9449 §5.2).
    pub dpop_bound_access_tokens: bool,
}

/// Finds a tenant's client registrations; the storage layer implements it.
pub trait ClientDirectory {
    /// The registration of `client_id` in `tenant`, when there is one.
    fn find(&self, tenant: &TenantId, client_id: &ClientId) -> Option<ClientRegistration>;
}
