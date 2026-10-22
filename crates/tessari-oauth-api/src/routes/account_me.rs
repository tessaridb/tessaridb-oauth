//! `GET /{tenant}/account/api/me`: what the signed-in user's account holds, for their own page.
//!
//! It needs the session this issuer opened for the browser and reads that session's user alone: the address they sign
//! in with and whether it is verified, and their sign-in factors as facts: whether a password is set, whether an
//! authenticator app is enrolled, how many recovery codes are left, and each passkey by its credential id with when it
//! was registered and whether it may be synced. No secret, hash or key is ever part of it. No answer may be stored by
//! a cache.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::login::signed_in;
use crate::state::PublicState;
use crate::{Error, Result};

#[derive(Serialize)]
struct Me {
    email: String,
    email_verified: bool,
    factors: Factors,
}

#[derive(Serialize)]
struct Factors {
    password: bool,
    totp: bool,
    recovery_codes: usize,
    passkeys: Vec<Passkey>,
}

#[derive(Serialize)]
struct Passkey {
    id: String,
    created_at: u64,
    synced: bool,
}

pub(super) async fn me(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let now = (state.clock)();
    let user = signed_in(&state, &tenant, &headers, now).await?.user;
    // A session names an account that existed when it signed in, and accounts are never removed.
    let account = state
        .users
        .find(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Internal)?;
    let password = state
        .users
        .password(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .is_some();
    let summary = state
        .factors
        .summary(&tenant, &user)
        .await
        .map_err(Error::Store)?;
    let passkeys = state
        .passkeys
        .list(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .into_iter()
        .map(|listed| Passkey {
            id: listed.id,
            created_at: listed.created_at.unix_secs(),
            synced: listed.synced,
        })
        .collect();
    let me = Me {
        email: account.email.as_str().to_owned(),
        email_verified: account.email_verified,
        factors: Factors {
            password,
            totp: summary.totp,
            recovery_codes: summary.recovery_codes,
            passkeys,
        },
    };
    Ok((StatusCode::OK, Json(me)).into_response())
}
