//! The ID token's claim set (OpenID Connect Core §2, §3.1.3.6): a statement that this user authenticated to this
//! client at this time — assembled from the authentication result and the request, never from the user record, so it
//! carries no profile data. `nonce`, `acr` and `amr` appear only when the request carried one or the ceremony verified
//! one; `at_hash` binds the ID token to the access token issued beside it.

use serde::Serialize;
use sha2::{Digest, Sha256};
use tessari_oauth_constants::ID_TOKEN_TTL_SECS;
use tessari_oauth_types::{Algorithm, ClientId, Timestamp, base64url};

/// The JOSE `typ` an ID token is signed under.
pub const TYPE: &str = "JWT";

/// How much of the digest `at_hash` keeps: its left half (OpenID Connect Core §3.1.3.6) — sixteen bytes of SHA-256.
const AT_HASH_BYTES: usize = 16;

/// What the authentication established, and for whom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authenticated<'a> {
    /// The tenant's issuer identifier.
    pub issuer: &'a str,
    /// The subject as this client knows it: the user's pairwise identifier.
    pub subject: &'a str,
    /// The client the ID token is for, its only audience.
    pub client_id: &'a ClientId,
    /// When the user authenticated.
    pub auth_time: Timestamp,
    /// The request's `nonce`, echoed unchanged.
    pub nonce: Option<&'a str>,
    /// The authentication context class the ceremony reached.
    pub acr: Option<&'a str>,
    /// The methods the ceremony verified.
    pub amr: &'a [&'a str],
    /// The session the authentication belongs to, as logout will name it.
    pub session_id: &'a str,
}

/// Every claim an ID token can carry, in the order [`Claims`] writes them: the `claims_supported` the metadata lists.
pub(crate) const CLAIM_NAMES: [&str; 11] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
    "at_hash",
];

/// The claims, in the order they are written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
    auth_time: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<&'a str>,
    #[serde(skip_serializing_if = "<[&str]>::is_empty")]
    amr: &'a [&'a str],
    sid: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    at_hash: Option<String>,
}

/// The algorithm the ID token is signed with has no `at_hash` digest this server knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no at_hash digest is known for the ID token's algorithm")]
pub struct DigestUnknown;

/// The claims of an ID token for `authenticated`, issued at `now`, beside `access_token` signed as the ID token is.
///
/// # Errors
///
/// [`DigestUnknown`] when an access token is given and the ID token's algorithm has no known `at_hash` digest.
pub fn claims<'a>(
    authenticated: &Authenticated<'a>,
    now: Timestamp,
    access_token: Option<(&str, Algorithm)>,
) -> Result<Claims<'a>, DigestUnknown> {
    let issued = now.unix_secs();
    Ok(Claims {
        iss: authenticated.issuer,
        sub: authenticated.subject,
        // The client alone: an ID token naming a resource server would be accepted there as an access token.
        aud: authenticated.client_id.as_str(),
        exp: issued.saturating_add(ID_TOKEN_TTL_SECS),
        iat: issued,
        auth_time: authenticated.auth_time.unix_secs(),
        nonce: authenticated.nonce,
        acr: authenticated.acr,
        amr: authenticated.amr,
        sid: authenticated.session_id,
        at_hash: access_token
            .map(|(token, algorithm)| at_hash(token, algorithm))
            .transpose()?,
    })
}

/// The left half of the digest of the ASCII `token` under the hash `algorithm` signs with, base64url.
fn at_hash(token: &str, algorithm: Algorithm) -> Result<String, DigestUnknown> {
    match algorithm {
        Algorithm::Es256 => {
            let digest = Sha256::digest(token.as_bytes());
            let (left, _) = digest.as_slice().split_at(AT_HASH_BYTES);
            Ok(base64url::encode(left))
        }
        // Ed25519 names no hash of its own; until the digest is settled no EdDSA ID token carries an access token.
        Algorithm::EdDsa => Err(DigestUnknown),
    }
}

#[cfg(test)]
#[path = "id_token_tests.rs"]
mod tests;
