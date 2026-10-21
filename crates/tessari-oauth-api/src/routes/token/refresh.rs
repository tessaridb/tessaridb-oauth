//! Redeeming a refresh token (RFC 6749 §6): judged on its family's grant, then rotated once.
//!
//! Every check that can refuse — the client, the DPoP key a bound family needs, the scope, the audience — runs on
//! the family's grant before the token is rotated, so a refused request leaves the token as it was. The rotation
//! spends the token atomically; a token that was already spent revokes its whole family and is recorded as a
//! security event. A refresh never gains authority:
//! the access token carries the scopes asked for, at most the grant's, and the family keeps its grant unchanged.

use tessari_oauth_core::clients::ClientRegistration;
use tessari_oauth_core::dpop::ProofUse;
use tessari_oauth_core::token::{self, Endpoint, Redemption};
use tessari_oauth_core::{Params, Reason, refresh};
use tessari_oauth_storage::refresh::{Rotation, RotationRefusal};
use tessari_oauth_types::ErrorCode;

use super::answer::Issued;
use super::redeem::{fresh_refresh_token, sign};
use super::{Failure, proof, refusal};
use crate::Error;
use crate::state::PublicState;

pub(super) async fn refresh(
    state: &PublicState,
    endpoint: &Endpoint,
    client: &ClientRegistration,
    params: &Params,
    proof: Option<&ProofUse>,
) -> Result<Issued, Failure> {
    let tenant = &endpoint.tenant;
    let invalid_grant = |reason| refusal(ErrorCode::InvalidGrant, reason);
    let presented = refresh::presented(params)?;
    let grant = state
        .refresh
        .grant(tenant, &presented)
        .await
        .map_err(Error::Store)?
        .ok_or(invalid_grant(Reason::RefreshUnknown))?;
    // Nothing about another client's grant is judged, so its scope and resources are never an oracle.
    if grant.client_id != client.client_id {
        return Err(invalid_grant(Reason::RefreshOtherClient).into());
    }
    if let Some(bound) = &grant.bound_to {
        match proof {
            None => return Err(refusal(ErrorCode::InvalidDpopProof, Reason::DpopMissing).into()),
            Some(proof) if proof.thumbprint != *bound => {
                return Err(invalid_grant(Reason::RefreshOtherKey).into());
            }
            Some(_) => {}
        }
    }
    let redemption = Redemption {
        scopes: refresh::scopes(params, &grant.scopes)?,
        audience: token::audience(params, &grant.resources)?,
        client_id: grant.client_id,
        user: grant.user,
    };
    let subject = state
        .subjects
        .pairwise(
            tenant,
            &state.kek,
            &redemption.client_id,
            &redemption.user,
            endpoint.now,
        )
        .await
        .map_err(Error::Store)?;
    // Taken before the rotation, so a tenant with no key to sign with spends no token.
    let signer = state
        .keys
        .signer(tenant, &state.kek, endpoint.now)
        .await
        .map_err(Error::Store)?;
    proof::spend(state, endpoint, proof).await?;
    let next = fresh_refresh_token()?;
    let rotation = state
        .refresh
        .rotate(
            tenant,
            &presented,
            &next,
            &redemption.client_id,
            endpoint.now,
        )
        .await
        .map_err(Error::Store)?;
    match rotation {
        Rotation::Rotated(_) => {}
        Rotation::Reused(_) => {
            tracing::warn!(
                event = "refresh_reused",
                tenant = tenant.as_str(),
                client = redemption.client_id.as_str(),
                "a rotated refresh token was presented again; its family is revoked"
            );
            return Err(invalid_grant(Reason::RefreshReused).into());
        }
        Rotation::Refused(why) => {
            return Err(invalid_grant(match why {
                RotationRefusal::Unknown => Reason::RefreshUnknown,
                RotationRefusal::Expired => Reason::RefreshExpired,
                RotationRefusal::FamilyRevoked => Reason::RefreshRevoked,
                RotationRefusal::OtherClient => Reason::RefreshOtherClient,
            })
            .into());
        }
    }
    let bound_to = proof.map(|proof| &proof.thumbprint);
    let access_token = sign(&signer, endpoint, &redemption, &subject, bound_to)?;
    Ok(Issued::new(
        access_token,
        Some(&next),
        &redemption.scopes,
        bound_to,
    ))
}
