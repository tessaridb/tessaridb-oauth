//! A company's user accounts in its console: opened, disabled and enabled by an operator holding `users`, each move
//! made only from the status the account is in. Disabling ends everything the account holds at once: its sessions
//! (each one's clients told through the back channel), its refresh families, and with its issuer sessions any console
//! session of its own. Enabling gives back only the right to sign in.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::ACCESS_TOKEN_TTL_SECS;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::refresh::Holder;
use tessari_oauth_storage::users::{Registered, UserStatus};
use tessari_oauth_types::{EmailAddress, TenantId, Timestamp, UserId};

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::users_read::masked;
use crate::{Error, Result};

/// The change `POST .../api/users` names.
const CREATE: &str = "users.create";
/// The change `POST .../api/users/{id}/disable` names.
const DISABLE: &str = "users.disable";
/// The change `POST .../api/users/{id}/enable` names.
const ENABLE: &str = "users.enable";
/// The reason the cascade of a disabled account is recorded under.
const USER_DISABLED: &str = "user_disabled";

/// A move of an account: why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Move {
    reason: String,
}

impl Reasoned for Move {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// An account to open: the address it signs in with, and why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Opening {
    email: String,
    reason: String,
}

impl Reasoned for Opening {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// An account opened: whose, its address masked, and its status.
#[derive(Serialize)]
struct Opened<'a> {
    user: &'a str,
    email: String,
    status: &'static str,
}

/// An account enabled: whose, and its status now.
#[derive(Serialize)]
struct Enabled<'a> {
    user: &'a str,
    status: &'static str,
}

/// An account disabled: whose, its status now, how many sessions and refresh families ended with it, and when the
/// access tokens already issued to it stop working.
#[derive(Serialize)]
struct Disabled<'a> {
    user: &'a str,
    status: &'static str,
    sessions: usize,
    families: usize,
    access_tokens_end_by: u64,
}

/// Open an account of `company` for the address the request names; an address already taken is refused.
pub(super) async fn create(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let users = std::sync::Arc::clone(&state.users);
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, CREATE),
        |operator, sent: Opening| async move {
            let email = EmailAddress::parse(sent.email.as_str()).map_err(|_| Error::Invalid)?;
            match users
                .register(&operator.tenant, &email, now)
                .await
                .map_err(Error::Store)?
            {
                Registered::Created(user) => {
                    let body = serde_json::to_string(&Opened {
                        user: user.as_str(),
                        email: masked(&email),
                        status: UserStatus::Active.name(),
                    })
                    .map_err(|_| Error::Internal)?;
                    Ok(Made {
                        status: StatusCode::CREATED,
                        body,
                        user: Some(user),
                    })
                }
                Registered::AddressTaken => Ok(Made {
                    status: StatusCode::CONFLICT,
                    body: serde_json::to_string(&Refusal {
                        code: "email_taken",
                        message: "an account of this company already signs in with this address",
                    })
                    .map_err(|_| Error::Internal)?,
                    user: None,
                }),
            }
        },
    )
    .await
}

/// Disable the account `user` of `company`, only while it is active, and end everything it holds.
pub(super) async fn disable(
    State(state): State<AdminState>,
    Path((company, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let moving = state.clone();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, DISABLE),
        |operator, _: Move| async move {
            let user = account(&user)?;
            let tenant = &operator.tenant;
            let now = (moving.clock)();
            let moved = moving
                .users
                .set_status(tenant, &user, UserStatus::Active, UserStatus::Disabled)
                .await
                .map_err(Error::Store)?;
            if !moved {
                let found = moving
                    .users
                    .find(tenant, &user)
                    .await
                    .map_err(Error::Store)?;
                if let Some(account) = &found
                    && account.status == UserStatus::Disabled
                {
                    // A disable whose cascade did not finish is completed by sending it again.
                    end_everything(&moving, tenant, &user, now).await?;
                }
                return unmoved(found.is_some(), user);
            }
            let (sessions, families) = end_everything(&moving, tenant, &user, now).await?;
            let access_tokens_end_by = now
                .unix_secs()
                .checked_add(ACCESS_TOKEN_TTL_SECS)
                .ok_or(Error::Internal)?;
            let body = serde_json::to_string(&Disabled {
                user: user.as_str(),
                status: UserStatus::Disabled.name(),
                sessions,
                families,
                access_tokens_end_by,
            })
            .map_err(|_| Error::Internal)?;
            Ok(Made {
                status: StatusCode::OK,
                body,
                user: Some(user),
            })
        },
    )
    .await
}

/// Enable the account `user` of `company`, only while it is disabled.
pub(super) async fn enable(
    State(state): State<AdminState>,
    Path((company, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let moving = state.clone();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, ENABLE),
        |operator, _: Move| async move {
            let user = account(&user)?;
            let tenant = &operator.tenant;
            let moved = moving
                .users
                .set_status(tenant, &user, UserStatus::Disabled, UserStatus::Active)
                .await
                .map_err(Error::Store)?;
            if !moved {
                let found = moving
                    .users
                    .find(tenant, &user)
                    .await
                    .map_err(Error::Store)?;
                return unmoved(found.is_some(), user);
            }
            let body = serde_json::to_string(&Enabled {
                user: user.as_str(),
                status: UserStatus::Active.name(),
            })
            .map_err(|_| Error::Internal)?;
            Ok(Made {
                status: StatusCode::OK,
                body,
                user: Some(user),
            })
        },
    )
    .await
}

/// The account a path names; one outside the grammar is no account of this company.
fn account(user: &str) -> Result<UserId> {
    UserId::parse(user).map_err(|_| Error::NotFound)
}

/// End every session and revoke every refresh family of `user`, answering how many of each ended.
async fn end_everything(
    state: &AdminState,
    tenant: &TenantId,
    user: &UserId,
    now: Timestamp,
) -> Result<(usize, usize)> {
    let sessions = state
        .sessions
        .end_all(tenant, user, None, now)
        .await
        .map_err(Error::Store)?;
    let families = state
        .refresh
        .revoke_standing(tenant, &Holder::User(user), USER_DISABLED, now)
        .await
        .map_err(Error::Store)?;
    Ok((sessions, families))
}

/// The answer to a move that changed nothing: the account is in the other status already, or is not this company's.
fn unmoved(exists: bool, user: UserId) -> Result<Made> {
    let (status, refusal) = if exists {
        (
            StatusCode::CONFLICT,
            Refusal {
                code: "changed_meanwhile",
                message: "the account is not in the status this move starts from; read it again",
            },
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Refusal {
                code: "user_not_found",
                message: "this company has no such account",
            },
        )
    };
    Ok(Made {
        status,
        body: serde_json::to_string(&refusal).map_err(|_| Error::Internal)?,
        user: exists.then_some(user),
    })
}
