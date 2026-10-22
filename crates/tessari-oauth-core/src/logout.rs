//! The `id_token_hint` a logout request carries (OpenID Connect RP-Initiated Logout 1.0 §2).
//!
//! The hint names which session the client wants ended and for whom; it is never authentication. It must be an ID
//! token this tenant signed, under the configured algorithm and the tenant's published keys, for this issuer, and it
//! is read however old it is, since a client logs a user out long after the token it holds has expired.

use serde::Deserialize;

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

#[cfg(test)]
#[path = "logout_tests.rs"]
mod tests;
