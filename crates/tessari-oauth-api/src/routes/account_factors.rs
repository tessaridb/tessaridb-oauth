//! `POST /{tenant}/account/api/passkeys/remove` and `POST /{tenant}/account/api/recovery-codes`: the signed-in user
//! removes one of their own passkeys, or replaces their recovery codes with a new set shown once.
//!
//! A change to how the account signs in needs a recent sign-in that reached the level the account's second factor
//! gives, or the user signs in again first (`reauthentication_required`). The passkey is found among the session's
//! user's own, so another user's id removes nothing, and the account's last way to sign in is refused
//! (`last_sign_in_method`). A removal signs out every other session of the user, revokes every refresh family the user
//! holds, because a credential the user no longer trusts may have opened them, and is recorded. New recovery codes
//! replace every unspent one, are answered once and never kept or recorded in the clear, and end the same things.
//! Bodies are JSON and the session cookie is `SameSite=Lax`, so a cross-site page can do neither. No answer may be
//! stored by a cache.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::ACCESS_TOKEN_TTL_SECS;
use tessari_oauth_core::factor_change::factor_change;
use tessari_oauth_infrastructure::custody::{recovery_codes, recovery_digest};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::passkeys::ListedPasskey;
use tessari_oauth_storage::refresh::Holder;
use tessari_oauth_storage::sessions::Session;
use tessari_oauth_types::{TenantId, Timestamp};

use super::login::{body, record, signed_in};
use crate::state::PublicState;
use crate::{Error, Result};

/// The reason every refresh family is revoked for when the user changes a sign-in factor.
const FACTOR_CHANGED: &str = "factor_changed";

#[derive(Deserialize)]
pub(super) struct Removal {
    id: String,
}

#[derive(Serialize)]
struct NotRemoved {
    removed: bool,
}

/// The body of a request that carries nothing; it is JSON so that a cross-site form cannot send it.
#[derive(Deserialize)]
pub(super) struct Nothing {}

/// New recovery codes, shown this once, and what issuing them ended.
#[derive(Serialize)]
struct Issued {
    codes: Vec<String>,
    sessions: usize,
    families: usize,
    access_tokens_end_by: u64,
}

/// What a removal ended with it.
#[derive(Serialize)]
struct Removed {
    removed: bool,
    sessions: usize,
    families: usize,
    access_tokens_end_by: u64,
}

pub(super) async fn remove_passkey(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Removal>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let removal = body(read)?;
    let now = (state.clock)();
    let asking = signed_in(&state, &tenant, &headers, now).await?;
    let user = asking.user.clone();
    let passkeys = may_change(&state, &tenant, &asking, now).await?;
    if !passkeys.iter().any(|passkey| passkey.id == removal.id) {
        return Ok((StatusCode::OK, Json(NotRemoved { removed: false })).into_response());
    }
    let password = state
        .users
        .password(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .is_some();
    if !password && passkeys.len() == 1 {
        return Err(Error::LastSignInMethod);
    }
    if !state
        .passkeys
        .remove(&tenant, &user, &removal.id)
        .await
        .map_err(Error::Store)?
    {
        return Ok((StatusCode::OK, Json(NotRemoved { removed: false })).into_response());
    }
    let (sessions, families, access_tokens_end_by) =
        changed(&state, &tenant, &asking, "passkey_removed", now).await?;
    let removed = Removed {
        removed: true,
        sessions,
        families,
        access_tokens_end_by,
    };
    Ok((StatusCode::OK, Json(removed)).into_response())
}

pub(super) async fn issue_recovery_codes(
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
    let codes = recovery_codes().map_err(|_| Error::Internal)?;
    let digests = codes
        .iter()
        .map(|code| recovery_digest(code).ok_or(Error::Internal))
        .collect::<Result<Vec<_>>>()?;
    state
        .factors
        .issue_recovery_codes(&tenant, &asking.user, &digests, now)
        .await
        .map_err(Error::Store)?;
    let (sessions, families, access_tokens_end_by) =
        changed(&state, &tenant, &asking, "recovery_codes_issued", now).await?;
    let issued = Issued {
        codes,
        sessions,
        families,
        access_tokens_end_by,
    };
    Ok((StatusCode::OK, Json(issued)).into_response())
}

/// The passkeys of the user of `asking`, once its session may change that user's sign-in factors at `now`.
pub(super) async fn may_change(
    state: &PublicState,
    tenant: &TenantId,
    asking: &Session,
    now: Timestamp,
) -> Result<Vec<ListedPasskey>> {
    let passkeys = state
        .passkeys
        .list(tenant, &asking.user)
        .await
        .map_err(Error::Store)?;
    let summary = state
        .factors
        .summary(tenant, &asking.user)
        .await
        .map_err(Error::Store)?;
    let signed_in_for = now.unix_secs().saturating_sub(asking.auth_time.unix_secs());
    let holds_second_factor = summary.totp || !passkeys.is_empty();
    factor_change(asking.assessment.level, signed_in_for, holds_second_factor)
        .map_err(|_| Error::ReauthenticationRequired)?;
    Ok(passkeys)
}

/// After a change named `reason` to the factors of the user of `asking`: sign out the user's other sessions, revoke
/// every refresh family, record it, and answer how many of each ended and when issued access tokens stop working.
pub(super) async fn changed(
    state: &PublicState,
    tenant: &TenantId,
    asking: &Session,
    reason: &str,
    now: Timestamp,
) -> Result<(usize, usize, u64)> {
    let user = &asking.user;
    let sessions = state
        .sessions
        .end_all(tenant, user, Some(&asking.sid), now)
        .await
        .map_err(Error::Store)?;
    let families = state
        .refresh
        .revoke_standing(tenant, &Holder::User(user), FACTOR_CHANGED, now)
        .await
        .map_err(Error::Store)?;
    let event = AuditEvent {
        user: Some(user.clone()),
        reason: Some(reason.to_owned()),
        families: Some(u64::try_from(families).map_err(|_| Error::Internal)?),
        ..AuditEvent::of(AuditKind::FactorChanged)
    };
    record(state, tenant, &event, now).await;
    let access_tokens_end_by = now
        .unix_secs()
        .checked_add(ACCESS_TOKEN_TTL_SECS)
        .ok_or(Error::Internal)?;
    Ok((sessions, families, access_tokens_end_by))
}
