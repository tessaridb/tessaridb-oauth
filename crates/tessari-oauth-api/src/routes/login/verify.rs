//! `POST /{tenant}/login/api/verify`: the page a verification link opens proves the user reads the address their
//! account signs in with, and the address is marked verified.
//!
//! A verification mail is sent when the signed-in user asks for one and when an account sets its first password. Its
//! link carries a token in the fragment, which reaches neither the server's logs nor a `Referer`; the token works once,
//! for a day, for the account and the address it was sent for, and a newer link replaces it. A token that was never
//! issued, was spent, was replaced, has lapsed or names an address the account no longer holds gets one answer. Values
//! are never logged, recorded or echoed.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tessari_oauth_constants::LOGIN_PATH;
use tessari_oauth_core::mail_template::{MailKind, Placeholder};
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{EmailAddress, TenantId, Timestamp, UserId, VerifyToken, base64url};

use super::{body, record};
use crate::routes::mail::compose;
use crate::state::PublicState;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(in crate::routes) struct Verification {
    token: String,
}

/// Mail `address`, the address `user` of `tenant` at `issuer` signs in with, a link that verifies it.
pub(in crate::routes) async fn send_verification(
    state: &PublicState,
    tenant: &TenantId,
    issuer: &str,
    user: &UserId,
    address: &EmailAddress,
    now: Timestamp,
) -> Result<()> {
    let token = VerifyToken::from_secret(base64url::encode(
        &random_secret().map_err(|_| Error::Internal)?,
    ));
    state
        .verifications
        .issue(tenant, &token, user, address, now)
        .await
        .map_err(Error::Store)?;
    let link = format!("{issuer}{LOGIN_PATH}/verify#token={}", token.expose());
    let mail = compose(
        &state.mail_templates,
        tenant,
        MailKind::Verify,
        Some(address.clone()),
        &[(Placeholder::Issuer, issuer), (Placeholder::Link, &link)],
    )
    .await?;
    state
        .outbox
        .enqueue(tenant, &state.kek, &mail)
        .await
        .map_err(Error::Store)
}

pub(in crate::routes) async fn complete_verification(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    read: std::result::Result<Json<Verification>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let Verification { token } = body(read)?;
    let now = (state.clock)();
    let (user, address) = state
        .verifications
        .redeem(&tenant, &VerifyToken::from_secret(token))
        .await
        .map_err(Error::Store)?
        .ok_or(Error::CodeRejected)?;
    // The address may have left the account since the link was sent; then the link verifies nothing.
    let marked = state
        .users
        .mark_verified(&tenant, &user, &address, now)
        .await
        .map_err(Error::Store)?;
    if !marked {
        return Err(Error::CodeRejected);
    }
    let event = AuditEvent {
        user: Some(user),
        ..AuditEvent::of(AuditKind::AddressVerified)
    };
    record(&state, &tenant, &event, now).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}
