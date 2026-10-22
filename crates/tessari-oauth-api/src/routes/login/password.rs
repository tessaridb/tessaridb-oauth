//! `POST /{tenant}/login/api/password`: prove the identified account with its password.
//!
//! The step is taken only where the sign-in waits for a first factor. Before anything is hashed, the three keys a
//! failure counts against are asked for a hold: the identified address's key the sign-in kept, the address the
//! request came from, and the pair of the two. A held key answers the same wait for every address. An account's
//! password is then checked; an address that names no account is checked against a hash of the same cost and never
//! matches. Every mismatch is one failure, answered alike and counted against all three keys; a match moves the
//! sign-in on and forgets the address's failures.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::{Extension, Json};
use serde::Deserialize;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::ceremony::{Identity, Stage};
use tessari_oauth_core::signin::SigninKey;
use tessari_oauth_infrastructure::custody::Verdict;
use tessari_oauth_types::{TenantId, UserId};

use super::{binding, body, rejected, unless_held, verified};
use crate::state::PublicState;
use crate::throttle::ClientAddress;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(in crate::routes) struct Password {
    password: String,
}

pub(in crate::routes) async fn password(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    Extension(ClientAddress(source)): Extension<ClientAddress>,
    headers: HeaderMap,
    read: std::result::Result<Json<Password>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let binding = binding(&headers)?;
    let Password { password } = body(read)?;
    let now = (state.clock)();
    let signin = state
        .signins
        .resume(&tenant, &binding, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SigninGone)?;
    let (Stage::FirstFactor, Some(account), Some(identity)) = (
        signin.ceremony.stage(),
        signin.account,
        signin.ceremony.identity().cloned(),
    ) else {
        return Err(Error::StepRefused);
    };
    let pair = state
        .passwords
        .signin_keys()
        .pair(tenant.as_str(), &account, &password);
    let keys = [
        (SigninKey::Account, account.as_str()),
        (SigninKey::Source, source.as_str()),
        (SigninKey::Pair, pair.as_str()),
    ];
    unless_held(&state, &keys, now).await?;
    let user = match identity {
        Identity::Known { user, .. } => Some(user),
        Identity::Unknown => None,
    };
    if !proves(&state, &tenant, user.as_ref(), &password).await? {
        return Err(rejected(&state, &tenant, &keys, user, now).await);
    }
    verified(
        &state,
        (&tenant, issuer),
        &binding,
        &account,
        Method::Password,
    )
    .await
}

/// Whether `password` is the password of `user` in `tenant`; with no user, or a user with no password, it is checked
/// against a hash of the same cost and is not.
async fn proves(
    state: &PublicState,
    tenant: &TenantId,
    user: Option<&UserId>,
    password: &str,
) -> Result<bool> {
    let stored = match user {
        Some(user) => state
            .users
            .password(tenant, user)
            .await
            .map_err(Error::Store)?,
        None => None,
    };
    let verdict = state
        .passwords
        .verify(password, stored.as_ref().map(|stored| stored.hash.as_str()))
        .await
        .map_err(|_| Error::Internal)?;
    Ok(matches!(verdict, Verdict::Match { .. }))
}
