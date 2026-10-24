//! DPoP proofs at the token endpoint and at a resource (RFC 9449 §4.3, §5, §7.1).
//!
//! A proof shows the client holds the private key of the public key it carries; it authenticates nobody. What it
//! yields is that key's thumbprint, which the minted token names in `cnf.jkt`, so the token is worthless without the
//! key. Every field is checked, because each closes a different hole: `typ` keeps a proof from passing as another
//! JWT, the server's algorithm list keeps the proof from choosing its verification, `htm` and `htu` bind it to this
//! request, `iat` to now, and `jti` — recorded by the caller until the window closes — to one use. At a resource the
//! proof also carries `ath`, the hash of the access token it accompanies (§4.3 check 12), so it cannot be moved to
//! another token.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tessari_oauth_constants::{CLOCK_SKEW_SECS, DPOP_PROOF_WINDOW_SECS, JTI_MAX_LEN};
use tessari_oauth_types::{ErrorCode, KeyThumbprint, Timestamp, base64url};
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
    ath: Option<String>,
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
    checked(proof, method, target, now).map(|(used, _)| used)
}

/// Verify `proof` for a request with `method` to `target` at `now` that presents `access_token` to a resource.
///
/// # Errors
///
/// As [`verify_proof`], and [`Reason::DpopClaims`] when `ath` is absent or is not the base64url SHA-256 of the ASCII
/// `access_token`.
pub fn verify_resource_proof(
    proof: &str,
    method: &str,
    target: &str,
    access_token: &str,
    now: Timestamp,
) -> Result<ProofUse, Refusal> {
    let (used, ath) = checked(proof, method, target, now)?;
    let expected = base64url::encode(Sha256::digest(access_token.as_bytes()).as_slice());
    if ath.as_deref() != Some(expected.as_str()) {
        return Err(refuse(Reason::DpopClaims));
    }
    Ok(used)
}

/// The checks every proof passes, leaving what it spends and the `ath` it carried.
fn checked(
    proof: &str,
    method: &str,
    target: &str,
    now: Timestamp,
) -> Result<(ProofUse, Option<String>), Refusal> {
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
    let used = ProofUse {
        thumbprint: key.thumbprint().clone(),
        jti,
        expires_at,
    };
    Ok((used, claims.ath))
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
/// The key a pushed request binds its code to (RFC 9449 §10.1): the `dpop_jkt` it names and the key of the proof it
/// came with must be one key, and either alone names it.
///
/// # Errors
///
/// `invalid_dpop_proof` with [`Reason::DpopKeyNotBound`] when the proof was made by another key than `dpop_jkt`.
pub fn bound_key(
    dpop_jkt: Option<&KeyThumbprint>,
    proof: Option<&ProofUse>,
) -> Result<Option<KeyThumbprint>, Refusal> {
    match (dpop_jkt, proof) {
        (Some(named), Some(proof)) if *named != proof.thumbprint => {
            Err(refuse(Reason::DpopKeyNotBound))
        }
        (Some(named), _) => Ok(Some(named.clone())),
        (None, Some(proof)) => Ok(Some(proof.thumbprint.clone())),
        (None, None) => Ok(None),
    }
}

/// A code bound to a key redeems only with a proof made by that key (RFC 9449 §10).
///
/// # Errors
///
/// `invalid_dpop_proof` with [`Reason::DpopMissing`] when no proof came, or [`Reason::DpopKeyNotBound`] when it was
/// made by another key.
pub fn holds_bound_key(
    bound: Option<&KeyThumbprint>,
    proof: Option<&ProofUse>,
) -> Result<(), Refusal> {
    match (bound, proof) {
        (None, _) => Ok(()),
        (Some(_), None) => Err(refuse(Reason::DpopMissing)),
        (Some(bound), Some(proof)) if *bound == proof.thumbprint => Ok(()),
        (Some(_), Some(_)) => Err(refuse(Reason::DpopKeyNotBound)),
    }
}

const fn refuse(reason: Reason) -> Refusal {
    Refusal {
        error: ErrorCode::InvalidDpopProof,
        reason,
    }
}

#[cfg(test)]
#[path = "dpop_tests.rs"]
mod tests;
