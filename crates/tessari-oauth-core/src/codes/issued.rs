//! The record an authorization code points at, carrying every binding a redemption must re-check.

use tessari_oauth_types::{Challenge, ClientId, ScopeSet, TenantId, Timestamp};

/// An issued authorization code's bindings. Stored under the code's hash; the code itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCode {
    /// The tenant whose issuer minted the code.
    pub tenant: TenantId,
    /// The only client that may redeem it.
    pub client_id: ClientId,
    /// The redirect URI exactly as the authorization request named it; redemption must repeat it byte for byte.
    pub redirect_uri: String,
    /// The PKCE challenge — never the verifier, which the server must be unable to compute.
    pub challenge: Challenge,
    /// The scopes granted with the code.
    pub scopes: ScopeSet,
    /// The instant after which the code no longer redeems.
    pub expires_at: Timestamp,
}
