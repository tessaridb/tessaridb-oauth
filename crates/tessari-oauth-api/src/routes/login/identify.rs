//! `POST /{tenant}/login/api/identify`: say which account is signing in.
//!
//! An address naming an active account identifies it, with whether a second factor must follow; any other address,
//! whether it names no account or one that may not sign in, identifies nobody. The sign-in moves on either way and the answer is
//! the same, so the step says nothing about which addresses have accounts; a sign-in for nobody never completes.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use tessari_oauth_core::ceremony::Identity;
use tessari_oauth_storage::users::UserStatus;
use tessari_oauth_types::{EmailAddress, TenantId};

use super::{answer, binding, body, step};
use crate::state::PublicState;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(in crate::routes) struct Identify {
    email: String,
}

pub(in crate::routes) async fn identify(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Identify>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let binding = binding(&headers)?;
    let Identify { email } = body(read)?;
    let email = EmailAddress::parse(&email).map_err(|_| Error::Invalid)?;
    let identity = identity(&state, &tenant, &email).await?;
    // Failures are counted under the address identified here, whatever a later step sends.
    let account = state
        .passwords
        .signin_keys()
        .account(tenant.as_str(), email.as_str());
    let stage = step(&state, &tenant, &binding, Some(account), |ceremony| {
        ceremony.identify(identity)
    })
    .await?;
    Ok(answer(stage, None))
}

/// Who `email` names in `tenant`.
async fn identity(
    state: &PublicState,
    tenant: &TenantId,
    email: &EmailAddress,
) -> Result<Identity> {
    let found = state
        .users
        .find_by_email(tenant, email)
        .await
        .map_err(Error::Store)?;
    let Some(account) = found.filter(|account| account.status == UserStatus::Active) else {
        return Ok(Identity::Unknown);
    };
    let second_factor = state
        .factors
        .totp(tenant, &state.kek, &account.user)
        .await
        .map_err(Error::Store)?
        .is_some();
    Ok(Identity::Known {
        user: account.user,
        second_factor,
    })
}
