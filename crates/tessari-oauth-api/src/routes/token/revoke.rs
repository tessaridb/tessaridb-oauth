//! `POST /{tenant}/oauth2/revoke` (RFC 7009): a client revokes one of its refresh tokens, and with it the token's
//! whole family, since a token cannot be revoked without its successors. An unknown token is answered as a revoked
//! one (§2.2), and a `token_type_hint` is only a hint (§2.1). An access token is refused as a type this server does
//! not revoke (§2.2.1): it lives out its five minutes, and a client must never be told it was recalled.

use axum::http::HeaderMap;
use tessari_oauth_core::token::Endpoint;
use tessari_oauth_core::{Params, Reason};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::refresh::Revocation;
use tessari_oauth_types::{ClientId, ErrorCode, RefreshToken};

use super::{Failure, authenticate, refusal};
use crate::Error;
use crate::state::PublicState;

pub(super) async fn revoke(
    state: &PublicState,
    endpoint: &Endpoint,
    headers: &HeaderMap,
    params: &Params,
    client_id: Option<&ClientId>,
) -> Result<AuditEvent, Failure> {
    let client = authenticate(state, endpoint, headers, params, client_id).await?;
    let raw = params
        .get("token")
        .ok_or(refusal(ErrorCode::InvalidRequest, Reason::MissingParameter))?;
    if is_compact_jws(raw) {
        return Err(refusal(
            ErrorCode::UnsupportedTokenType,
            Reason::AccessTokenNotRevocable,
        )
        .into());
    }
    let revocation = state
        .refresh
        .revoke_token(
            &endpoint.tenant,
            &RefreshToken::from_secret(raw),
            &client.client_id,
            endpoint.now,
        )
        .await
        .map_err(Error::Store)?;
    let revoked = AuditEvent {
        client_id: Some(client.client_id),
        ..AuditEvent::of(AuditKind::RevokedByClient)
    };
    match revocation {
        Revocation::Revoked => Ok(revoked),
        // Answered as a revocation (§2.2), and recorded as the unknown token it was.
        Revocation::Unknown => Ok(AuditEvent {
            reason: Some(format!("{:?}", Reason::RefreshUnknown)),
            ..revoked
        }),
        Revocation::OtherClient => {
            Err(refusal(ErrorCode::InvalidGrant, Reason::RefreshOtherClient).into())
        }
    }
}

/// Whether `raw` has the shape of a compact JWS — three segments — which an access token has and a refresh token,
/// base64url without dots, never does.
fn is_compact_jws(raw: &str) -> bool {
    raw.split('.').count() == 3
}
