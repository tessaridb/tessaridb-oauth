//! Redeeming a spent code: its bindings checked, its refresh family started, its access token signed.

use tessari_oauth_core::access_token::{self, Grant, TYPE};
use tessari_oauth_core::clients::{ClientRegistration, GrantType};
use tessari_oauth_core::codes::IssuedCode;
use tessari_oauth_core::token::{self, Endpoint, Redemption};
use tessari_oauth_core::{Params, Reason};
use tessari_oauth_infrastructure::custody::{SigningKey, random_secret, token_id};
use tessari_oauth_storage::codes::Consumed;
use tessari_oauth_storage::refresh::RefreshGrant;
use tessari_oauth_types::{AuthorizationCode, ErrorCategory, ErrorCode, RefreshToken, base64url};

use super::answer::Issued;
use super::{Failure, refusal};
use crate::Error;
use crate::state::PublicState;

/// Spend the code, check every binding, then start the refresh family and sign the access token.
pub(super) async fn redeem(
    state: &PublicState,
    endpoint: &Endpoint,
    client: &ClientRegistration,
    params: &Params,
) -> Result<Issued, Failure> {
    let tenant = &endpoint.tenant;
    let code = AuthorizationCode::from_secret(
        params
            .get("code")
            .ok_or(refusal(ErrorCode::InvalidRequest, Reason::MissingParameter))?,
    );
    let issued = match state
        .codes
        .consume(tenant, &code, endpoint.now)
        .await
        .map_err(Error::Store)?
    {
        Consumed::Fresh(issued) => issued,
        Consumed::Absent => {
            return Err(refusal(ErrorCode::InvalidGrant, Reason::CodeUnknown).into());
        }
        Consumed::Replayed(issued) => {
            state
                .refresh
                .revoke_for_replay(&family_grant(&issued), &code.digest(), endpoint.now)
                .await
                .map_err(Error::Store)?;
            tracing::warn!(
                event = "code_replayed",
                tenant = tenant.as_str(),
                client = issued.client_id.as_str(),
                "a redeemed code was presented again; the refresh family it started is revoked"
            );
            return Err(refusal(ErrorCode::InvalidGrant, Reason::CodeReplayed).into());
        }
    };
    let redemption = token::redeem_code(tenant, client, params, &issued, endpoint.now)?;
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
    // Taken before the family is started, so a tenant with no key to sign with starts nothing.
    let signer = state
        .keys
        .signer(tenant, &state.kek, endpoint.now)
        .await
        .map_err(Error::Store)?;
    let refresh_token = if client.grant_types.contains(&GrantType::RefreshToken) {
        Some(start_family(state, endpoint, &issued, &code).await?)
    } else {
        None
    };
    let access_token = sign(&signer, endpoint, &redemption, &subject)?;
    Ok(Issued::bearer(
        access_token,
        refresh_token.as_ref(),
        &redemption.scopes,
    ))
}

/// The authority a code's refresh family carries: everything the code granted.
fn family_grant(issued: &IssuedCode) -> RefreshGrant {
    RefreshGrant {
        tenant: issued.tenant.clone(),
        user: issued.user.clone(),
        client_id: issued.client_id.clone(),
        scopes: issued.scopes.clone(),
        resources: issued.resources.clone(),
    }
}

/// Start the refresh family of `code` — its id is the code's digest — with a fresh first token.
async fn start_family(
    state: &PublicState,
    endpoint: &Endpoint,
    issued: &IssuedCode,
    code: &AuthorizationCode,
) -> Result<RefreshToken, Failure> {
    let first = fresh_refresh_token()?;
    match state
        .refresh
        .start(&first, &family_grant(issued), &code.digest(), endpoint.now)
        .await
    {
        Ok(()) => Ok(first),
        // A replay of this code revoked the family before it was started: nothing is issued from it.
        Err(store) if store.category() == ErrorCategory::Conflict => {
            Err(refusal(ErrorCode::InvalidGrant, Reason::CodeFamilyRevoked).into())
        }
        Err(store) => Err(Error::Store(store).into()),
    }
}

/// A new refresh token: 256 bits from the system's cryptographic random source, base64url.
pub(super) fn fresh_refresh_token() -> Result<RefreshToken, Failure> {
    let secret = random_secret().map_err(|_| Error::Internal)?;
    Ok(RefreshToken::from_secret(base64url::encode(&secret)))
}

/// The access token for `redemption`, issued to `subject` and signed by `signer`, the tenant's current key.
pub(super) fn sign(
    signer: &SigningKey,
    endpoint: &Endpoint,
    redemption: &Redemption,
    subject: &str,
) -> Result<String, Failure> {
    let jti = token_id().map_err(|_| Error::Internal)?;
    let grant = Grant {
        issuer: &endpoint.issuer,
        audience: &redemption.audience,
        subject,
        client_id: &redemption.client_id,
        scopes: &redemption.scopes,
        bound_to: None,
    };
    let payload = serde_json::to_vec(&access_token::claims(&grant, &jti, endpoint.now))
        .map_err(|_| Error::Internal)?;
    Ok(signer
        .sign_compact(TYPE, &payload)
        .map_err(|_| Error::Internal)?)
}
