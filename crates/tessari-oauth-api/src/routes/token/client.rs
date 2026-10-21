//! The client credentials grant (RFC 6749 §4.4): a confidential client's own token, with no user behind it.
//!
//! The client is already authenticated by its pinned method. Its token names the client itself as the subject
//! (RFC 9068 §2.2), so nothing in it reads as a user, and it comes with no refresh token (RFC 6749 §4.4.3): the client
//! authenticates again instead.

use tessari_oauth_core::Params;
use tessari_oauth_core::access_token::Grant;
use tessari_oauth_core::client_credentials;
use tessari_oauth_core::clients::ClientRegistration;
use tessari_oauth_core::dpop::ProofUse;
use tessari_oauth_core::token::Endpoint;

use super::answer::Issued;
use super::redeem::sign_grant;
use super::{Failure, proof};
use crate::Error;
use crate::state::PublicState;

pub(super) async fn client_credentials(
    state: &PublicState,
    endpoint: &Endpoint,
    client: &ClientRegistration,
    params: &Params,
    proof: Option<&ProofUse>,
) -> Result<Issued, Failure> {
    let granted = client_credentials::grant(params, client)?;
    let signer = state
        .keys
        .signer(&endpoint.tenant, &state.kek, endpoint.now)
        .await
        .map_err(Error::Store)?;
    proof::spend(state, endpoint, proof).await?;
    let bound_to = proof.map(|proof| &proof.thumbprint);
    let grant = Grant {
        issuer: &endpoint.issuer,
        audience: &granted.audience,
        subject: client.client_id.as_str(),
        client_id: &client.client_id,
        scopes: &granted.scopes,
        bound_to,
    };
    let access_token = sign_grant(&signer, endpoint, &grant)?;
    Ok(Issued::new(access_token, None, &granted.scopes, bound_to))
}
