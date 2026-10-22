//! `POST /{tenant}/account/api/totp/begin` and `POST /{tenant}/account/api/totp/confirm`: the signed-in user enrols an
//! authenticator app.
//!
//! Both need a session that may change the account's factors (a recent sign-in at the account's level). Beginning
//! draws a secret from the system random source, keeps it sealed for this session for ten minutes, and answers it
//! once, in base32 and as the Key URI an app scans; an account that already has an app is refused
//! (`already_enrolled`). Confirming takes the pending secret once: a code from it enrols the app, spends that code's
//! step, signs out the user's other sessions, revokes every refresh family and is recorded; a wrong code ends the
//! attempt, so a code is never guessed against one secret twice. The secret is never logged or recorded. Bodies are
//! JSON and the session cookie is `SameSite=Lax`, so a cross-site page can do neither. No answer may be stored by a
//! cache.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::TOTP_SECRET_BYTES;
use tessari_oauth_core::totp::{provisioning, verify};
use tessari_oauth_infrastructure::custody::random_secret;

use super::account_factors::{Nothing, changed, may_change};
use super::login::{body, signed_in};
use crate::state::PublicState;
use crate::{Error, Result};

/// The secret to enter in an app, shown this once.
#[derive(Serialize)]
struct Begun {
    secret: String,
    uri: String,
}

#[derive(Deserialize)]
pub(super) struct Confirmation {
    code: String,
}

/// What enrolling the app ended with it.
#[derive(Serialize)]
struct Enrolled {
    sessions: usize,
    families: usize,
    access_tokens_end_by: u64,
}

pub(super) async fn begin(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Nothing>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    body(read)?;
    let now = (state.clock)();
    let asking = signed_in(&state, &tenant, &headers, now).await?;
    may_change(&state, &tenant, &asking, now).await?;
    let summary = state
        .factors
        .summary(&tenant, &asking.user)
        .await
        .map_err(Error::Store)?;
    if summary.totp {
        return Err(Error::AlreadyEnrolled);
    }
    // A session names an account that existed when it signed in, and accounts are never removed.
    let account = state
        .users
        .find(&tenant, &asking.user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Internal)?;
    let drawn = random_secret().map_err(|_| Error::Internal)?;
    let secret = drawn.get(..TOTP_SECRET_BYTES).ok_or(Error::Internal)?;
    state
        .factors
        .begin_totp(&tenant, &state.kek, &asking.user, &asking.sid, secret, now)
        .await
        .map_err(Error::Store)?;
    let (secret, uri) = provisioning(tenant.as_str(), account.email.as_str(), secret);
    Ok((StatusCode::OK, Json(Begun { secret, uri })).into_response())
}

pub(super) async fn confirm(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Confirmation>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let confirmation = body(read)?;
    let now = (state.clock)();
    let asking = signed_in(&state, &tenant, &headers, now).await?;
    may_change(&state, &tenant, &asking, now).await?;
    let secret = state
        .factors
        .take_pending_totp(&tenant, &state.kek, &asking.user, &asking.sid)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::NothingPending)?;
    let step = verify(&secret, &confirmation.code, now, None).map_err(|_| Error::CodeRejected)?;
    state
        .factors
        .enroll_totp(&tenant, &state.kek, &asking.user, &secret, now)
        .await
        .map_err(Error::Store)?;
    state
        .factors
        .accept_step(&tenant, &asking.user, step)
        .await
        .map_err(Error::Store)?;
    let (sessions, families, access_tokens_end_by) =
        changed(&state, &tenant, &asking, "totp_enrolled", now).await?;
    let enrolled = Enrolled {
        sessions,
        families,
        access_tokens_end_by,
    };
    Ok((StatusCode::OK, Json(enrolled)).into_response())
}
