//! `POST /{tenant}/login/api/{totp,recovery}`: prove the identified account's second factor.
//!
//! Both steps are taken only where the sign-in waits for a second factor, after the password. Before a code is
//! checked, the identified address's key and the address the request came from are asked for a hold. A one-time
//! code is accepted once, for a step after the last one accepted; a recovery code is spent by being accepted, and its
//! use is recorded. A wrong, replayed or spent code is one failure, counted against both keys and answered as a wrong
//! password is; a value that cannot be a code at all is refused as unreadable and counts nothing.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{Extension, Json};
use serde::Deserialize;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::ceremony::{Identity, Stage};
use tessari_oauth_core::signin::SigninKey;
use tessari_oauth_core::totp::{self, TotpRefused};
use tessari_oauth_infrastructure::custody::recovery_digest;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{SigninBinding, TenantId, Timestamp, UserId};

use super::{binding, body, record, rejected, unless_held, verified};
use crate::state::PublicState;
use crate::throttle::ClientAddress;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(in crate::routes) struct Code {
    code: String,
}

pub(in crate::routes) async fn totp(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    Extension(ClientAddress(source)): Extension<ClientAddress>,
    headers: HeaderMap,
    read: std::result::Result<Json<Code>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let binding = binding(&headers)?;
    let Code { code } = body(read)?;
    let now = (state.clock)();
    let (user, account) = second_factor_due(&state, &tenant, &binding, now).await?;
    let keys = [
        (SigninKey::Account, account.as_str()),
        (SigninKey::Source, source.as_str()),
    ];
    unless_held(&state, &keys, now).await?;
    let factor = state
        .factors
        .totp(&tenant, &state.kek, &user)
        .await
        .map_err(Error::Store)?;
    let accepted = match factor {
        None => false,
        Some(factor) => match totp::verify(&factor.secret, &code, now, Some(factor.last_step)) {
            Err(TotpRefused::Malformed) => return Err(Error::Invalid),
            Err(TotpRefused::Wrong | TotpRefused::Replayed) => false,
            // A simultaneous step that took this code, or a later one, first leaves nothing to accept.
            Ok(step) => state
                .factors
                .accept_step(&tenant, &user, step)
                .await
                .map_err(Error::Store)?,
        },
    };
    if !accepted {
        return Err(rejected(&state, &tenant, &keys, Some(user), now).await);
    }
    verified(&state, &tenant, &binding, &account, Method::Totp).await
}

pub(in crate::routes) async fn recovery(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    Extension(ClientAddress(source)): Extension<ClientAddress>,
    headers: HeaderMap,
    read: std::result::Result<Json<Code>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let binding = binding(&headers)?;
    let Code { code } = body(read)?;
    let digest = recovery_digest(&code).ok_or(Error::Invalid)?;
    let now = (state.clock)();
    let (user, account) = second_factor_due(&state, &tenant, &binding, now).await?;
    let keys = [
        (SigninKey::Account, account.as_str()),
        (SigninKey::Source, source.as_str()),
    ];
    unless_held(&state, &keys, now).await?;
    let spent = state
        .factors
        .spend_recovery_code(&tenant, &user, &digest)
        .await
        .map_err(Error::Store)?;
    if !spent {
        return Err(rejected(&state, &tenant, &keys, Some(user), now).await);
    }
    tracing::warn!(
        event = "recovery_code_used",
        tenant = tenant.as_str(),
        "a recovery code stood in for a second factor"
    );
    let event = AuditEvent {
        user: Some(user),
        ..AuditEvent::of(AuditKind::RecoveryUsed)
    };
    record(&state, &tenant, &event, now).await;
    verified(&state, &tenant, &binding, &account, Method::RecoveryCode).await
}

/// The account the sign-in `binding` holds waits on a second factor for, with its counter key; [`Error::StepRefused`]
/// anywhere else.
async fn second_factor_due(
    state: &PublicState,
    tenant: &TenantId,
    binding: &SigninBinding,
    now: Timestamp,
) -> Result<(UserId, String)> {
    let signin = state
        .signins
        .resume(tenant, binding, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SigninGone)?;
    match (
        signin.ceremony.stage(),
        signin.ceremony.identity(),
        signin.account,
    ) {
        (Stage::SecondFactor, Some(Identity::Known { user, .. }), Some(account)) => {
            Ok((user.clone(), account))
        }
        _ => Err(Error::StepRefused),
    }
}
