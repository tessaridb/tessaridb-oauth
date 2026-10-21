//! DPoP proofs at the token endpoint (RFC 9449 §4.3, §5).
//!
//! A proof shows the client holds the private key of the public key it carries; it authenticates nobody. What it
//! yields is that key's thumbprint, which the minted token names in `cnf.jkt`, so the token is worthless without the
//! key. Every field is checked, because each closes a different hole: `typ` keeps a proof from passing as another
//! JWT, the server's algorithm list keeps the proof from choosing its verification, `htm` and `htu` bind it to this
//! request, `iat` to now, and `jti` — recorded by the caller until the window closes — to one use.

use serde::Deserialize;
use tessari_oauth_constants::{CLOCK_SKEW_SECS, DPOP_PROOF_WINDOW_SECS, JTI_MAX_LEN};
use tessari_oauth_types::{ErrorCode, KeyThumbprint, Timestamp};
use url::Url;

use crate::Reason;
use crate::jose::{self, Algorithm};
use crate::token::Refusal;

/// The only `typ` a proof may carry.
const PROOF_TYPE: &str = "dpop+jwt";

/// The algorithms a proof may be signed with — the server's list, never the proof's.
pub const ALGORITHMS: [Algorithm; 2] = [Algorithm::EdDsa, Algorithm::Es256];

/// What a verified proof leaves: the key to bind, and the `jti` to remember as spent until `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofUse {
    /// The thumbprint of the proof's key, for `cnf.jkt`.
    pub thumbprint: KeyThumbprint,
    /// The proof's `jti`.
    pub jti: String,
    /// The end of the proof's acceptance window.
    pub expires_at: Timestamp,
}

/// The claims read here; every other claim is ignored.
#[derive(Deserialize)]
struct Claims {
    jti: Option<String>,
    htm: String,
    htu: String,
    iat: u64,
}

/// Verify `proof` for a request with `method` to `target` at `now`.
///
/// # Errors
///
/// `invalid_dpop_proof`, naming the first check that failed: [`Reason::DpopProof`] for the header, the key or the
/// signature, [`Reason::DpopClaims`] for `jti`, `htm` or `htu`, [`Reason::DpopTime`] for `iat`.
pub fn verify_proof(
    proof: &str,
    method: &str,
    target: &str,
    now: Timestamp,
) -> Result<ProofUse, Refusal> {
    let (verified, key) =
        jose::verify_embedded(proof, &ALGORITHMS).map_err(|_| refuse(Reason::DpopProof))?;
    if verified.typ.as_deref() != Some(PROOF_TYPE) {
        return Err(refuse(Reason::DpopProof));
    }
    let claims: Claims =
        serde_json::from_slice(&verified.payload).map_err(|_| refuse(Reason::DpopClaims))?;
    if claims.htm != method || !same_target(&claims.htu, target) {
        return Err(refuse(Reason::DpopClaims));
    }
    let jti = claims
        .jti
        .filter(|jti| !jti.is_empty() && jti.chars().count() <= JTI_MAX_LEN)
        .ok_or(refuse(Reason::DpopClaims))?;
    let expires_at = fresh_until(claims.iat, now)?;
    Ok(ProofUse {
        thumbprint: key.thumbprint().clone(),
        jti,
        expires_at,
    })
}

/// Whether `claimed` and `target` name the same resource once each is normalised (RFC 3986 §6.2.2–6.2.3) and stripped
/// of query and fragment.
fn same_target(claimed: &str, target: &str) -> bool {
    let normalised = |raw: &str| {
        Url::parse(raw).ok().map(|mut uri| {
            uri.set_query(None);
            uri.set_fragment(None);
            uri
        })
    };
    matches!((normalised(claimed), normalised(target)), (Some(claimed), Some(target)) if claimed == target)
}

/// The end of the acceptance window of a proof created at `iat`, when `now` lies inside it: no older than the window,
/// and no further ahead than the clock skew.
fn fresh_until(iat: u64, now: Timestamp) -> Result<Timestamp, Refusal> {
    let now = now.unix_secs();
    let expires = iat
        .checked_add(DPOP_PROOF_WINDOW_SECS)
        .ok_or(refuse(Reason::DpopTime))?;
    let ahead = now
        .checked_add(CLOCK_SKEW_SECS)
        .is_none_or(|latest| iat > latest);
    if ahead || now > expires {
        return Err(refuse(Reason::DpopTime));
    }
    Ok(Timestamp::from_unix_secs(expires))
}

/// An `invalid_dpop_proof` refusal for `reason`.
const fn refuse(reason: Reason) -> Refusal {
    Refusal {
        error: ErrorCode::InvalidDpopProof,
        reason,
    }
}

#[cfg(test)]
#[path = "dpop_tests.rs"]
mod tests;
