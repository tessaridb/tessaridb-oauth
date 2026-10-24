//! `POST /{tenant}/login/api/email/confirm` and `.../email/cancel`: the page the two mails of an address change open.
//!
//! The new address confirms the change with its link within a day of the request; the change still waits until a
//! day has passed since the request, and the answer says when that is. The old address cancels the change with its
//! link until the change takes effect. A token that was never issued, was used, was replaced or has lapsed gets one
//! answer. Values are never logged, recorded or echoed.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{TenantId, Timestamp, UserId, VerifyToken};

use super::{body, record};
use crate::state::PublicState;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(in crate::routes) struct EmailLink {
    token: String,
}

/// When a confirmed change takes effect, in Unix seconds.
#[derive(Serialize)]
struct Confirmed {
    effective_at: u64,
}

pub(in crate::routes) async fn confirm_email_change(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    read: std::result::Result<Json<EmailLink>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let EmailLink { token } = body(read)?;
    let now = (state.clock)();
    let confirmed = state
        .email_changes
        .confirm(&tenant, &VerifyToken::from_secret(token), now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::CodeRejected)?;
    recorded(&state, &tenant, confirmed.user, "confirmed", now).await;
    let answer = Confirmed {
        effective_at: confirmed.effective_at.unix_secs(),
    };
    Ok((StatusCode::ACCEPTED, Json(answer)).into_response())
}

pub(in crate::routes) async fn cancel_email_change(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    read: std::result::Result<Json<EmailLink>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let EmailLink { token } = body(read)?;
    let now = (state.clock)();
    let (user, _) = state
        .email_changes
        .cancel(&tenant, &VerifyToken::from_secret(token))
        .await
        .map_err(Error::Store)?
        .ok_or(Error::CodeRejected)?;
    recorded(&state, &tenant, user, "cancelled", now).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn recorded(state: &PublicState, tenant: &TenantId, user: UserId, how: &str, now: Timestamp) {
    let event = AuditEvent {
        user: Some(user),
        reason: Some(how.to_owned()),
        ..AuditEvent::of(AuditKind::AddressChanged)
    };
    record(state, tenant, &event, now).await;
}
