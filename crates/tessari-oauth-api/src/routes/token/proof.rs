//! DPoP at the token endpoint (RFC 9449 §4.3, §5): at most one proof, verified for this very request, and its `jti`
//! spent only once every other check has passed — so a refused request never uses up a proof, and a proof never
//! buys a second request.

use axum::http::HeaderMap;
use tessari_oauth_constants::{PAR_PATH, TOKEN_PATH};
use tessari_oauth_core::Reason;
use tessari_oauth_core::clients::ClientRegistration;
use tessari_oauth_core::dpop::{self, ProofUse};
use tessari_oauth_core::token::{Endpoint, Refusal};
use tessari_oauth_storage::replay::Spent;
use tessari_oauth_types::ErrorCode;

use super::{Failure, refusal};
use crate::Error;
use crate::state::PublicState;

/// The header a proof travels in.
const DPOP: &str = "dpop";

/// The request's proof, verified for a POST to this tenant's token endpoint; `None` when it carries none and `client`
/// is not registered as bound.
pub(super) fn read(
    headers: &HeaderMap,
    endpoint: &Endpoint,
    client: &ClientRegistration,
) -> Result<Option<ProofUse>, Refusal> {
    let invalid = |reason| refusal(ErrorCode::InvalidDpopProof, reason);
    let mut proofs = headers.get_all(DPOP).iter();
    match (proofs.next(), proofs.next()) {
        (None, _) if client.dpop_bound_access_tokens => Err(invalid(Reason::DpopMissing)),
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err(invalid(Reason::DpopSeveralProofs)),
        (Some(proof), None) => {
            let proof = proof.to_str().map_err(|_| invalid(Reason::DpopProof))?;
            let target = format!("{}{TOKEN_PATH}", endpoint.issuer);
            dpop::verify_proof(proof, "POST", &target, endpoint.now).map(Some)
        }
    }
}

/// The proof a pushed request came with, verified for a POST to this tenant's PAR endpoint (RFC 9449 §10.1); `None`
/// when it carries none, which a pushed request may.
pub(super) fn read_pushed(
    headers: &HeaderMap,
    endpoint: &Endpoint,
) -> Result<Option<ProofUse>, Refusal> {
    let invalid = |reason| refusal(ErrorCode::InvalidDpopProof, reason);
    let mut proofs = headers.get_all(DPOP).iter();
    match (proofs.next(), proofs.next()) {
        (None, _) => Ok(None),
        (Some(_), Some(_)) => Err(invalid(Reason::DpopSeveralProofs)),
        (Some(proof), None) => {
            let proof = proof.to_str().map_err(|_| invalid(Reason::DpopProof))?;
            let target = format!("{}{PAR_PATH}", endpoint.issuer);
            dpop::verify_proof(proof, "POST", &target, endpoint.now).map(Some)
        }
    }
}

/// Spend `proof`'s `jti`, refusing a proof presented before.
pub(super) async fn spend(
    state: &PublicState,
    endpoint: &Endpoint,
    proof: Option<&ProofUse>,
) -> Result<(), Failure> {
    let Some(proof) = proof else {
        return Ok(());
    };
    let spent = state
        .replay
        .spend_proof(&endpoint.tenant, proof, endpoint.now)
        .await
        .map_err(Error::Store)?;
    if spent == Spent::Replayed {
        return Err(refusal(ErrorCode::InvalidDpopProof, Reason::DpopReplayed).into());
    }
    Ok(())
}
