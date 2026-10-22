//! Redeeming a spent code: its bindings checked, its proof spent, its refresh family started, its access token signed,
//! and, when the code was granted `openid`, an ID token stating how its user signed in, as the code recorded it.

use tessari_oauth_constants::OPENID_SCOPE;
use tessari_oauth_core::access_token::{self, Grant, TYPE};
use tessari_oauth_core::authentication::assess;
use tessari_oauth_core::clients::{AuthMethod, ClientRegistration, GrantType};
use tessari_oauth_core::codes::IssuedCode;
use tessari_oauth_core::dpop::ProofUse;
use tessari_oauth_core::id_token::{self, Authenticated};
use tessari_oauth_core::token::{self, Endpoint, Redemption};
use tessari_oauth_core::{Params, Reason};
use tessari_oauth_infrastructure::custody::{SigningKey, random_secret, token_id};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::codes::Consumed;
use tessari_oauth_storage::refresh::RefreshGrant;
use tessari_oauth_types::{
    AuthorizationCode, ErrorCategory, ErrorCode, KeyThumbprint, RefreshToken, base64url,
};

use super::answer::Issued;
use super::{Failure, audit, proof, refusal};
use crate::Error;
use crate::state::PublicState;

/// Spend the code, check every binding, spend the proof, then start the refresh family and sign the access token —
/// bound to the proof's key when there is one, and the family too when the client is public (RFC 9449 §5).
pub(super) async fn redeem(
    state: &PublicState,
    endpoint: &Endpoint,
    client: &ClientRegistration,
    params: &Params,
    proof: Option<&ProofUse>,
) -> Result<(Issued, AuditEvent), Failure> {
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
                .revoke_for_replay(&family_grant(&issued, None), &code.digest(), endpoint.now)
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
    proof::spend(state, endpoint, proof).await?;
    let bound_to = proof.map(|proof| &proof.thumbprint);
    // A confidential client's refresh is bound by its authentication; only a public client's family is bound to a key.
    let family_key = bound_to.filter(|_| client.auth_method == AuthMethod::None);
    let refresh_token = if client.grant_types.contains(&GrantType::RefreshToken) {
        Some(start_family(state, endpoint, &issued, &code, family_key).await?)
    } else {
        None
    };
    let grant = access_grant(endpoint, &redemption, &subject, bound_to);
    let signed = sign_grant(&signer, endpoint, &grant)?;
    let event = audit::issued(
        AuditKind::IssuedCode,
        &grant,
        signed.jti,
        Some(&redemption.user),
        client.auth_method,
    );
    let id_token = if redemption.scopes.iter().any(|scope| scope == OPENID_SCOPE) {
        Some(sign_id_token(
            &signer,
            endpoint,
            &issued,
            &subject,
            &signed.token,
        )?)
    } else {
        None
    };
    if id_token.is_some() {
        // The session now has a client to tell when it ends (OpenID Connect Back-Channel Logout 1.0).
        state
            .sessions
            .record_client(
                tenant,
                &redemption.user,
                &issued.authentication.sid,
                &redemption.client_id,
            )
            .await
            .map_err(Error::Store)?;
    }
    let answer = Issued::new(
        signed.token,
        refresh_token.as_ref(),
        &redemption.scopes,
        bound_to,
    );
    let answer = match id_token {
        Some(id_token) => answer.with_id_token(id_token),
        None => answer,
    };
    Ok((answer, event))
}

/// The ID token for the user `issued` names, known to its client as `subject`, beside `access_token`: when they
/// signed in, at the level and by the methods the code recorded, in the session the code names, with the request's
/// `nonce`.
fn sign_id_token(
    signer: &SigningKey,
    endpoint: &Endpoint,
    issued: &IssuedCode,
    subject: &str,
    access_token: &str,
) -> Result<String, Failure> {
    let assessment = assess(&issued.authentication.methods).ok_or(Error::Internal)?;
    let authenticated = Authenticated {
        issuer: &endpoint.issuer,
        subject,
        client_id: &issued.client_id,
        auth_time: issued.authentication.auth_time,
        nonce: issued.nonce.as_deref(),
        acr: Some(assessment.level.acr()),
        amr: &assessment.amr,
        session_id: &issued.authentication.sid,
    };
    let claims = id_token::claims(
        &authenticated,
        endpoint.now,
        Some((access_token, signer.algorithm())),
    )
    .map_err(|_| Error::Internal)?;
    let payload = serde_json::to_vec(&claims).map_err(|_| Error::Internal)?;
    signer
        .sign_compact(id_token::TYPE, &payload)
        .map_err(|_| Error::Internal.into())
}

/// The authority a code's refresh family carries: everything the code granted, bound to `key` when given.
fn family_grant(issued: &IssuedCode, key: Option<&KeyThumbprint>) -> RefreshGrant {
    RefreshGrant {
        tenant: issued.tenant.clone(),
        user: issued.user.clone(),
        client_id: issued.client_id.clone(),
        scopes: issued.scopes.clone(),
        resources: issued.resources.clone(),
        bound_to: key.cloned(),
    }
}

/// Start the refresh family of `code` — its id is the code's digest — with a fresh first token, bound to `key` when
/// given.
async fn start_family(
    state: &PublicState,
    endpoint: &Endpoint,
    issued: &IssuedCode,
    code: &AuthorizationCode,
    key: Option<&KeyThumbprint>,
) -> Result<RefreshToken, Failure> {
    let first = fresh_refresh_token()?;
    match state
        .refresh
        .start(
            &first,
            &family_grant(issued, key),
            &code.digest(),
            endpoint.now,
        )
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

/// An access token and the `jti` it carries, which the audit trail names in its place.
pub(super) struct Signed {
    pub(super) token: String,
    pub(super) jti: String,
}

/// What the access token for `redemption` grants: issued to `subject`, bound to `bound_to` when given.
pub(super) fn access_grant<'a>(
    endpoint: &'a Endpoint,
    redemption: &'a Redemption,
    subject: &'a str,
    bound_to: Option<&'a KeyThumbprint>,
) -> Grant<'a> {
    Grant {
        issuer: &endpoint.issuer,
        audience: &redemption.audience,
        subject,
        client_id: &redemption.client_id,
        scopes: &redemption.scopes,
        bound_to,
    }
}

/// The access token `grant` decided, signed by `signer`, the tenant's current key.
pub(super) fn sign_grant(
    signer: &SigningKey,
    endpoint: &Endpoint,
    grant: &Grant<'_>,
) -> Result<Signed, Failure> {
    let jti = token_id().map_err(|_| Error::Internal)?;
    let payload = serde_json::to_vec(&access_token::claims(grant, &jti, endpoint.now))
        .map_err(|_| Error::Internal)?;
    let token = signer
        .sign_compact(TYPE, &payload)
        .map_err(|_| Error::Internal)?;
    Ok(Signed { token, jti })
}
