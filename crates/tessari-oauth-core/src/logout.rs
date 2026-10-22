//! The `id_token_hint` a logout request carries (OpenID Connect RP-Initiated Logout 1.0 §2).
//!
//! The hint names which session the client wants ended and for whom; it is never authentication. It must be an ID
//! token this tenant signed, under the configured algorithm and the tenant's published keys, for this issuer, and it
//! is read however old it is, since a client logs a user out long after the token it holds has expired.
//!
//! The logout token (OpenID Connect Back-Channel Logout 1.0 §2.4) goes the other way: the issuer tells a client,
//! server to server, that a session it holds ended. It is typed `logout+jwt` so that it is never read as an ID token,
//! and carries the event instead of a `nonce`.

use serde::{Deserialize, Serialize};
use tessari_oauth_constants::LOGOUT_TOKEN_TTL_SECS;
use tessari_oauth_types::{ClientId, Timestamp};

use crate::id_token::TYPE;
use crate::jose::{self, Algorithm, VerifyingKey};

/// What a hint names: the client it was issued to, the user as that client knows them, and the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint {
    /// The client the ID token was issued to (`aud`).
    pub client_id: String,
    /// The subject the client knows the user by.
    pub subject: String,
    /// The session the ID token was issued in (`sid`).
    pub session_id: String,
}

/// Why a hint was not read; any of them ends nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintRefused {
    /// Not a token this tenant signed under its algorithm and keys.
    Unverified,
    /// Signed here, but not an ID token naming a session.
    NotAnIdToken,
    /// An ID token of another issuer.
    OtherIssuer,
}

/// The claims read here.
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    sid: String,
}

/// Read `token` as an ID token `issuer` signed with `algorithm` under one of `keys`.
///
/// # Errors
///
/// [`HintRefused`] naming the first check that failed.
pub fn read_hint(
    token: &str,
    issuer: &str,
    algorithm: Algorithm,
    keys: &[VerifyingKey],
) -> Result<Hint, HintRefused> {
    let verified = jose::verify(token, algorithm, keys).map_err(|_| HintRefused::Unverified)?;
    if verified.typ.as_deref() != Some(TYPE) {
        return Err(HintRefused::NotAnIdToken);
    }
    let claims: Claims =
        serde_json::from_slice(&verified.payload).map_err(|_| HintRefused::NotAnIdToken)?;
    if claims.iss != issuer {
        return Err(HintRefused::OtherIssuer);
    }
    Ok(Hint {
        client_id: claims.aud,
        subject: claims.sub,
        session_id: claims.sid,
    })
}

/// The JOSE `typ` a logout token is signed under (Back-Channel Logout 1.0 §2.4).
pub const LOGOUT_TOKEN_TYPE: &str = "logout+jwt";

/// A session that ended, as one client is told of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ended<'a> {
    /// The tenant's issuer identifier.
    pub issuer: &'a str,
    /// The client told, the token's only audience.
    pub client_id: &'a ClientId,
    /// The user as that client knows them: the pairwise subject.
    pub subject: &'a str,
    /// The session that ended (`sid`).
    pub session_id: &'a str,
}

/// The event member: one key, an empty object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Events {
    #[serde(rename = "http://schemas.openid.net/event/backchannel-logout")]
    backchannel_logout: Empty,
}

/// The empty object the event names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Empty {}

/// A logout token's claims, in the order they are written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogoutClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
    jti: &'a str,
    sid: &'a str,
    events: Events,
}

/// The claims of the logout token telling `ended`'s client its session ended, issued at `now` under `jti`.
#[must_use]
pub fn logout_claims<'a>(ended: &Ended<'a>, jti: &'a str, now: Timestamp) -> LogoutClaims<'a> {
    let issued = now.unix_secs();
    LogoutClaims {
        iss: ended.issuer,
        sub: ended.subject,
        aud: ended.client_id.as_str(),
        iat: issued,
        exp: issued.saturating_add(LOGOUT_TOKEN_TTL_SECS),
        jti,
        sid: ended.session_id,
        events: Events {
            backchannel_logout: Empty {},
        },
    }
}

#[cfg(test)]
#[path = "logout_tests.rs"]
mod tests;
