//! `private_key_jwt` client authentication (RFC 7523 §2.2, §3, with the audience rule of its 2025 update).
//!
//! The assertion is verified under the algorithm and keys the client registered, then every claim is checked. The
//! audience must be this tenant's issuer and nothing else: an assertion addressed to a token endpoint, or to several
//! parties, is one another server could have been handed and could replay here. The `jti` and the expiry are
//! returned so the caller records the assertion as spent; that record is what makes it single use.

use serde::Deserialize;
use tessari_oauth_constants::{CLIENT_ASSERTION_MAX_TTL_SECS, CLOCK_SKEW_SECS, JTI_MAX_LEN};
use tessari_oauth_types::{ClientId, ErrorCode, Timestamp};

use crate::Reason;
use crate::clients::{AuthMethod, ClientRegistration};
use crate::jose;
use crate::token::Refusal;

/// `typ` values a client-authentication JWT may carry; absent is accepted too.
const ACCEPTED_TYPES: [&str; 2] = ["client-authentication+jwt", "JWT"];

/// What a verified assertion leaves to be recorded as spent until it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionUse {
    /// The client that signed it.
    pub client_id: ClientId,
    /// Its `jti`.
    pub jti: String,
    /// Its `exp`: the `jti` must be remembered until then.
    pub expires_at: Timestamp,
}

/// `aud` as a string or an array of strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

/// The claims read here; every other claim is ignored.
#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    nbf: Option<u64>,
    jti: Option<String>,
}

/// Verify `compact` as `client`'s assertion for the tenant whose issuer is `issuer`, at `now`.
///
/// # Errors
///
/// `invalid_client`, naming the first check that failed: [`Reason::AssertionSignature`],
/// [`Reason::AssertionClaims`], [`Reason::AssertionAudience`] or [`Reason::AssertionTime`]. A client not pinned
/// to `private_key_jwt` has no keys to verify with and is refused as [`Reason::AssertionSignature`].
pub fn verify(
    compact: &str,
    client: &ClientRegistration,
    issuer: &str,
    now: Timestamp,
) -> Result<AssertionUse, Refusal> {
    let AuthMethod::PrivateKeyJwt(algorithm) = client.auth_method else {
        return Err(refuse(Reason::AssertionSignature));
    };
    let verified = jose::verify(compact, algorithm, &client.keys)
        .map_err(|_| refuse(Reason::AssertionSignature))?;
    if verified
        .typ
        .as_deref()
        .is_some_and(|typ| !ACCEPTED_TYPES.contains(&typ))
    {
        return Err(refuse(Reason::AssertionClaims));
    }
    let claims: Claims =
        serde_json::from_slice(&verified.payload).map_err(|_| refuse(Reason::AssertionClaims))?;
    let own = client.client_id.as_str();
    if claims.iss != own || claims.sub != own {
        return Err(refuse(Reason::AssertionClaims));
    }
    let sole_audience = match &claims.aud {
        Audience::One(aud) => aud == issuer,
        Audience::Many(auds) => matches!(auds.as_slice(), [aud] if aud == issuer),
    };
    if !sole_audience {
        return Err(refuse(Reason::AssertionAudience));
    }
    check_time(&claims, now)?;
    let jti = claims
        .jti
        .filter(|jti| !jti.is_empty() && jti.chars().count() <= JTI_MAX_LEN)
        .ok_or(refuse(Reason::AssertionClaims))?;
    Ok(AssertionUse {
        client_id: client.client_id.clone(),
        jti,
        expires_at: Timestamp::from_unix_secs(claims.exp),
    })
}

/// Unexpired, already valid, and not valid for longer than an assertion needs, each with the clock skew allowed.
fn check_time(claims: &Claims, now: Timestamp) -> Result<(), Refusal> {
    let now = now.unix_secs();
    let latest_expiry = now
        .checked_add(CLIENT_ASSERTION_MAX_TTL_SECS)
        .and_then(|bound| bound.checked_add(CLOCK_SKEW_SECS));
    let earliest_start = now.checked_add(CLOCK_SKEW_SECS);
    let expired = claims
        .exp
        .checked_add(CLOCK_SKEW_SECS)
        .is_none_or(|end| now >= end);
    let too_long = latest_expiry.is_none_or(|bound| claims.exp > bound);
    let not_yet = claims
        .nbf
        .is_some_and(|nbf| earliest_start.is_none_or(|start| nbf > start));
    if expired || too_long || not_yet {
        return Err(refuse(Reason::AssertionTime));
    }
    Ok(())
}

/// An `invalid_client` refusal for `reason`.
const fn refuse(reason: Reason) -> Refusal {
    Refusal {
        error: ErrorCode::InvalidClient,
        reason,
    }
}

#[cfg(test)]
#[path = "assertion_tests.rs"]
mod tests;
