//! The access token's claim set (RFC 9068 §2.2): who issued it, which one resource it is for, whom and which client
//! it acts for, which scopes it carries, and when it stops — nothing else, so no profile or entitlement data travels
//! through every proxy and log a token passes — and, for a DPoP-bound token, the key that must accompany it.

use serde::Serialize;
use tessari_oauth_constants::ACCESS_TOKEN_TTL_SECS;
use tessari_oauth_types::{ClientId, KeyThumbprint, Resource, ScopeSet, Timestamp};

/// The `typ` header of an access token (RFC 9068 §2.1), so a verifier cannot be handed an ID token, a client
/// assertion or a DPoP proof in its place.
pub const TYPE: &str = "at+jwt";

/// What a grant decided the token says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant<'a> {
    /// The tenant's issuer identifier.
    pub issuer: &'a str,
    /// The one resource the token is for; a token addressed to two is two tokens.
    pub audience: &'a Resource,
    /// The subject as this client knows it: the user's pairwise identifier, or the client id for a client's own token.
    pub subject: &'a str,
    /// The client the token is issued to.
    pub client_id: &'a ClientId,
    /// The scopes granted.
    pub scopes: &'a ScopeSet,
    /// The key a DPoP proof showed the client holds, when the token is bound to it (RFC 9449 §6); `None` for a
    /// bearer token.
    pub bound_to: Option<&'a KeyThumbprint>,
}

/// The confirmation claim of a bound token (RFC 7800 §3.1): the thumbprint of the key that must accompany it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct Confirmation<'a> {
    jkt: &'a str,
}

/// The claims, in the order they are written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claims<'a> {
    iss: &'a str,
    exp: u64,
    aud: &'a str,
    sub: &'a str,
    client_id: &'a str,
    iat: u64,
    jti: &'a str,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<Confirmation<'a>>,
}

/// The claims of a token for `grant`, identified by `jti`, issued at `now` and valid for the access-token lifetime.
#[must_use]
pub fn claims<'a>(grant: &Grant<'a>, jti: &'a str, now: Timestamp) -> Claims<'a> {
    let issued = now.unix_secs();
    Claims {
        iss: grant.issuer,
        exp: issued.saturating_add(ACCESS_TOKEN_TTL_SECS),
        aud: grant.audience.as_str(),
        sub: grant.subject,
        client_id: grant.client_id.as_str(),
        iat: issued,
        jti,
        scope: grant.scopes.iter().collect::<Vec<_>>().join(" "),
        cnf: grant.bound_to.map(|key| Confirmation { jkt: key.as_str() }),
    }
}

#[cfg(test)]
#[path = "access_token_tests.rs"]
mod tests;
