//! UserInfo's check of the access token it is handed (OpenID Connect Core §5.3, RFC 6750 §2.1, RFC 9449 §7.1).
//!
//! UserInfo is a resource of this server's own, so it judges a token as any resource server must, in an order that
//! keeps each check from confirming only itself: the signature under the configured algorithm and the tenant's
//! published keys, the token type, the tenant's issuer, this resource as the audience, the time, the key binding,
//! and only then the scope. The token comes from the `Authorization` header alone, which the caller reads.

use serde::Deserialize;
use tessari_oauth_constants::{CLOCK_SKEW_SECS, OPENID_SCOPE};
use tessari_oauth_types::{ErrorCode, Timestamp};

use crate::Reason;
use crate::access_token::TYPE;
use crate::dpop::{self, ProofUse};
use crate::jose::{self, Algorithm, VerifyingKey};
use crate::token::Refusal;

/// How the token arrived: under the `Bearer` scheme, or under `DPoP` with the request's `DPoP` header, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presented<'a> {
    /// `Authorization: Bearer <token>` (RFC 6750 §2.1).
    Bearer(&'a str),
    /// `Authorization: DPoP <token>` and the proof that came with it (RFC 9449 §7.1).
    Dpop {
        /// The access token.
        token: &'a str,
        /// The `DPoP` header, when there was exactly one.
        proof: Option<&'a str>,
    },
}

/// What the token must match: this tenant, this resource, this request.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The tenant's issuer identifier.
    pub issuer: &'a str,
    /// The UserInfo resource's own identifier, the only audience accepted.
    pub audience: &'a str,
    /// The algorithm the tenant signs with — the server's, never the token's.
    pub algorithm: Algorithm,
    /// The tenant's published verifying keys.
    pub keys: &'a [VerifyingKey],
    /// The request's method, for a DPoP proof's `htm`.
    pub method: &'a str,
    /// The request's URI, for a DPoP proof's `htu`.
    pub target: &'a str,
}

/// A token UserInfo may answer: whom it speaks for, and the proof to spend when it was DPoP-bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// The token's subject, as the client knows the user.
    pub subject: String,
    /// The DPoP proof that accompanied a bound token, whose `jti` the caller records as spent.
    pub proof: Option<ProofUse>,
}

/// The claims read here; a token missing any of them is not an access token this server issued.
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    exp: u64,
    iat: u64,
    scope: String,
    cnf: Option<Confirmation>,
}

/// A bound token's confirmation (RFC 7800 §3.1).
#[derive(Deserialize)]
struct Confirmation {
    jkt: String,
}

/// Judge `presented` against `expected` at `now`.
///
/// # Errors
///
/// `invalid_token` naming the first check that failed, `invalid_dpop_proof` for a bound token whose proof is missing
/// or does not hold, `insufficient_scope` for a token without `openid`.
pub fn verify(
    presented: Presented<'_>,
    expected: &Expected<'_>,
    now: Timestamp,
) -> Result<Access, Refusal> {
    let (token, proof) = match presented {
        Presented::Bearer(token) => (token, None),
        Presented::Dpop { token, proof } => (token, Some(proof)),
    };
    let verified = jose::verify(token, expected.algorithm, expected.keys)
        .map_err(|_| invalid(Reason::AccessTokenUnverified))?;
    if verified.typ.as_deref() != Some(TYPE) {
        return Err(invalid(Reason::AccessTokenType));
    }
    let claims: Claims =
        serde_json::from_slice(&verified.payload).map_err(|_| invalid(Reason::AccessTokenType))?;
    if claims.iss != expected.issuer {
        return Err(invalid(Reason::AccessTokenIssuer));
    }
    if claims.aud != expected.audience {
        return Err(invalid(Reason::AccessTokenAudience));
    }
    check_time(&claims, now)?;
    let proof = match (claims.cnf, proof) {
        (None, None) => None,
        (Some(confirmation), Some(proof)) => {
            let proof = proof.ok_or(Refusal {
                error: ErrorCode::InvalidDpopProof,
                reason: Reason::DpopMissing,
            })?;
            let used =
                dpop::verify_resource_proof(proof, expected.method, expected.target, token, now)?;
            if used.thumbprint.as_str() != confirmation.jkt {
                return Err(invalid(Reason::AccessTokenBinding));
            }
            Some(used)
        }
        // A bound token presented as a bearer token, or an unbound one under DPoP (RFC 9449 §7.1).
        (Some(_), None) | (None, Some(_)) => return Err(invalid(Reason::AccessTokenBinding)),
    };
    if !claims.scope.split(' ').any(|scope| scope == OPENID_SCOPE) {
        return Err(Refusal {
            error: ErrorCode::InsufficientScope,
            reason: Reason::ScopeWithoutOpenId,
        });
    }
    Ok(Access {
        subject: claims.sub,
        proof,
    })
}

/// Unexpired and not issued ahead of the clock, each with the clock skew allowed.
fn check_time(claims: &Claims, now: Timestamp) -> Result<(), Refusal> {
    let now = now.unix_secs();
    let expired = claims
        .exp
        .checked_add(CLOCK_SKEW_SECS)
        .is_none_or(|end| now >= end);
    let ahead = now
        .checked_add(CLOCK_SKEW_SECS)
        .is_none_or(|latest| claims.iat > latest);
    if expired || ahead {
        return Err(invalid(Reason::AccessTokenTime));
    }
    Ok(())
}

/// An `invalid_token` refusal for `reason`.
const fn invalid(reason: Reason) -> Refusal {
    Refusal {
        error: ErrorCode::InvalidToken,
        reason,
    }
}

#[cfg(test)]
#[path = "userinfo_tests.rs"]
mod tests;
