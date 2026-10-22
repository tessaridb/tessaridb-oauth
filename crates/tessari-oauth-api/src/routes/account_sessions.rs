//! `/{tenant}/account/api/sessions`: the signed-in user's own sessions at this issuer, and the way to end them.
//!
//! Every request needs the session this issuer opened for the browser and acts for that session's user alone: the
//! list shows that user's live sessions by public id with when each signed in, when it was last used and how, and
//! marks the one asking; never a cookie or what it is stored under. Ending one by its public id ends it only among
//! that user's own, so another user's id ends nothing. Signing out everywhere ends every session of the user, the
//! one asking included, and every refresh family the user holds at any client, and answers when the access tokens
//! already issued stop working. Each ending is recorded. Bodies are JSON and the session cookie is `SameSite=Lax`, so
//! a cross-site page can do neither. No answer may be stored by a cache.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::ACCESS_TOKEN_TTL_SECS;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::refresh::Holder;
use tessari_oauth_types::{TenantId, Timestamp, UserId};

use super::login::{body, record, signed_in};
use crate::state::PublicState;
use crate::{Error, Result};

/// The reason the refresh families are revoked for when a user signs out everywhere.
const SIGNED_OUT_EVERYWHERE: &str = "logged_out_everywhere";

/// One session as the list shows it.
#[derive(Serialize)]
struct Listed {
    sid: String,
    signed_in_at: u64,
    last_seen_at: u64,
    methods: Vec<&'static str>,
    current: bool,
}

#[derive(Serialize)]
struct Sessions {
    sessions: Vec<Listed>,
}

#[derive(Deserialize)]
pub(super) struct Ending {
    sid: String,
}

#[derive(Serialize)]
struct Ended {
    ended: bool,
}

/// Every session and family that signing out everywhere ended.
#[derive(Serialize)]
struct EndedEverywhere {
    sessions: usize,
    families: usize,
    access_tokens_end_by: u64,
}

/// Unused fields of the sign-out-everywhere body; the body is JSON so that a cross-site form cannot send it.
#[derive(Deserialize)]
pub(super) struct Everywhere {}

pub(super) async fn sessions(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let now = (state.clock)();
    let asking = signed_in(&state, &tenant, &headers, now).await?;
    let sessions = state
        .sessions
        .list(&tenant, &asking.user, now)
        .await
        .map_err(Error::Store)?
        .into_iter()
        .map(|listed| Listed {
            current: listed.sid == asking.sid,
            signed_in_at: listed.auth_time.unix_secs(),
            last_seen_at: listed.seen_at.unix_secs(),
            methods: listed.methods.iter().map(|method| method.name()).collect(),
            sid: listed.sid,
        })
        .collect();
    Ok((StatusCode::OK, Json(Sessions { sessions })).into_response())
}

pub(super) async fn end(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Ending>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let ending = body(read)?;
    let now = (state.clock)();
    let asking = signed_in(&state, &tenant, &headers, now).await?;
    let ended = state
        .sessions
        .end_sid(&tenant, &asking.user, &ending.sid)
        .await
        .map_err(Error::Store)?;
    if ended {
        recorded(&state, &tenant, &asking.user, ("one", None), now).await;
    }
    Ok((StatusCode::OK, Json(Ended { ended })).into_response())
}

pub(super) async fn end_all(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Everywhere>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    body(read)?;
    let now = (state.clock)();
    let user = signed_in(&state, &tenant, &headers, now).await?.user;
    let sessions = state
        .sessions
        .end_all(&tenant, &user, None, now)
        .await
        .map_err(Error::Store)?;
    let families = state
        .refresh
        .revoke_standing(&tenant, &Holder::User(&user), SIGNED_OUT_EVERYWHERE, now)
        .await
        .map_err(Error::Store)?;
    let count = u64::try_from(families).map_err(|_| Error::Internal)?;
    recorded(&state, &tenant, &user, ("everywhere", Some(count)), now).await;
    let access_tokens_end_by = now
        .unix_secs()
        .checked_add(ACCESS_TOKEN_TTL_SECS)
        .ok_or(Error::Internal)?;
    let ended = EndedEverywhere {
        sessions,
        families,
        access_tokens_end_by,
    };
    Ok((StatusCode::OK, Json(ended)).into_response())
}

/// Record that `user` ended sessions in `tenant`: `which` of them, and how many refresh families went with them.
async fn recorded(
    state: &PublicState,
    tenant: &TenantId,
    user: &UserId,
    (which, families): (&str, Option<u64>),
    now: Timestamp,
) {
    let event = AuditEvent {
        user: Some(user.clone()),
        reason: Some(which.to_owned()),
        families,
        ..AuditEvent::of(AuditKind::SessionsEnded)
    };
    record(state, tenant, &event, now).await;
}
