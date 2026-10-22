//! The record an authorization code points at, carrying every binding a redemption must re-check.

use std::collections::BTreeSet;

use tessari_oauth_types::{Challenge, ClientId, Resource, ScopeSet, TenantId, Timestamp, UserId};

use crate::authentication::Method;

/// An issued authorization code's bindings. Stored under the code's hash; the code itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCode {
    /// The tenant whose issuer minted the code.
    pub tenant: TenantId,
    /// The only client that may redeem it.
    pub client_id: ClientId,
    /// The user who authorised it; the tokens it redeems for act for this user and nobody else.
    pub user: UserId,
    /// The redirect URI exactly as the authorization request named it; redemption must repeat it byte for byte.
    pub redirect_uri: String,
    /// The PKCE challenge — never the verifier, which the server must be unable to compute.
    pub challenge: Challenge,
    /// The scopes granted with the code.
    pub scopes: ScopeSet,
    /// The resources the scopes were granted at; each token redeemed from the code is addressed to one of them.
    pub resources: BTreeSet<Resource>,
    /// The instant after which the code no longer redeems.
    pub expires_at: Timestamp,
    /// How the user signed in before the code was issued, which an ID token redeemed from it states.
    pub authentication: CodeAuthentication,
    /// The authorization request's `nonce`, echoed unchanged in the ID token.
    pub nonce: Option<String>,
}

/// The sign-in behind a code: when it happened, the methods it verified (from which its `acr` and `amr` are derived
/// again when they are stated), and the session it opened, by that session's public id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeAuthentication {
    /// When the user signed in.
    pub auth_time: Timestamp,
    /// The methods the sign-in verified, in order.
    pub methods: Vec<Method>,
    /// The session's public id.
    pub sid: String,
}
