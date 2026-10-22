//! A company's operators in its console. Authority over a role is holding it: an operator lists the grants of the
//! roles they hold, and grants or revokes only those, only for active accounts of their own company, never for
//! themselves. A grant made here always expires; none is permanent.

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::{
    OPERATOR_GRANT_DEFAULT_DAYS, OPERATOR_GRANT_MAX_DAYS, OPERATOR_PAGE_MAX,
};
use tessari_oauth_storage::operators::{Granted, OperatorGrant, OperatorRole};
use tessari_oauth_storage::users::UserStatus;
use tessari_oauth_types::{Timestamp, UserId};

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply, reason_of};
use super::operator::signed_in;
use crate::{Error, Result};

/// The change `POST .../operators/{user}/grants/{role}` names.
const GRANT: &str = "operators.grant";
/// The change `POST .../operators/{user}/grants/{role}/revoke` names.
const REVOKE: &str = "operators.revoke";
/// Seconds in a day, for a grant's validity.
const DAY_SECS: u64 = 86_400;

/// A page of grants asked for: after a grant (`<user>.<role>`), and how many.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Listing {
    after: Option<String>,
    limit: Option<u32>,
}

/// A grant asked for: why, and for how many days.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Granting {
    reason: String,
    valid_days: Option<u64>,
}

impl Reasoned for Granting {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// A revocation asked for: why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revoking {
    reason: String,
}

impl Reasoned for Revoking {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// One grant as the console shows it.
#[derive(Serialize)]
struct Shown {
    user: String,
    role: &'static str,
    granted_by: String,
    granted_at: u64,
    expires_at: Option<u64>,
    reason: String,
}

/// A page of grants, and the cursor of the next one when this one is full.
#[derive(Serialize)]
struct Page {
    operators: Vec<Shown>,
    next: Option<String>,
}

/// A revocation made.
#[derive(Serialize)]
struct Revoked<'a> {
    user: &'a str,
    role: &'static str,
    revoked: bool,
}

/// The current grants of the roles the viewer holds.
pub(super) async fn list(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    listing: std::result::Result<Query<Listing>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    let Query(listing) = listing.map_err(|_| Error::Invalid)?;
    let limit = listing.limit.unwrap_or(OPERATOR_PAGE_MAX);
    if !(1..=OPERATOR_PAGE_MAX).contains(&limit) {
        return Err(Error::Invalid);
    }
    let after = listing.after.as_deref().map(anchor).transpose()?;
    let grants = state
        .operators
        .page(
            &operator.tenant,
            &operator.roles,
            after.as_ref().map(|(user, role)| (user, *role)),
            limit,
            (state.clock)(),
        )
        .await
        .map_err(Error::Store)?;
    let full = u32::try_from(grants.len()).is_ok_and(|count| count == limit);
    let next = grants
        .last()
        .filter(|_| full)
        .map(|grant| format!("{}.{}", grant.user.as_str(), grant.role.name()));
    let operators = grants.into_iter().map(shown).collect();
    Ok(Json(Page { operators, next }).into_response())
}

/// Grant `role` to the account `user`, by an operator who holds it.
pub(super) async fn grant(
    State(state): State<AdminState>,
    Path((company, user, role)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let role = OperatorRole::parse(&role).ok_or(Error::NotFound)?;
    let granting = state.clone();
    apply(
        &state,
        (&company, &headers, &body),
        (role, GRANT),
        |operator, sent: Granting| async move {
            let days = sent.valid_days.unwrap_or(OPERATOR_GRANT_DEFAULT_DAYS);
            if !(1..=OPERATOR_GRANT_MAX_DAYS).contains(&days) {
                return Err(Error::Invalid);
            }
            let found = match UserId::parse(user) {
                Ok(user) => granting
                    .users
                    .find(&operator.tenant, &user)
                    .await
                    .map_err(Error::Store)?,
                Err(_) => None,
            };
            let Some(account) = found else {
                return refused(StatusCode::NOT_FOUND, "user_not_found", None);
            };
            if account.status == UserStatus::Disabled {
                return refused(StatusCode::CONFLICT, "account_disabled", Some(account.user));
            }
            let now = (granting.clock)();
            let expires_at = days
                .checked_mul(DAY_SECS)
                .and_then(|span| now.unix_secs().checked_add(span))
                .map(Timestamp::from_unix_secs)
                .ok_or(Error::Invalid)?;
            let grant = OperatorGrant {
                user: account.user,
                role,
                granted_by: operator.user.as_str().to_owned(),
                granted_at: now,
                reason: reason_of(&sent)?,
                expires_at: Some(expires_at),
            };
            match granting
                .operators
                .grant(&operator.tenant, &grant)
                .await
                .map_err(Error::Store)?
            {
                Granted::Granted => Ok(Made {
                    status: StatusCode::OK,
                    body: serde_json::to_string(&shown(grant.clone()))
                        .map_err(|_| Error::Internal)?,
                    shown: None,
                    user: Some(grant.user),
                }),
                Granted::SelfGrant => refused(StatusCode::CONFLICT, "self_grant", Some(grant.user)),
                Granted::AboveCeiling => {
                    refused(StatusCode::CONFLICT, "above_ceiling", Some(grant.user))
                }
            }
        },
    )
    .await
}

/// Take `role` from the account `user`, by an operator who holds it.
pub(super) async fn revoke(
    State(state): State<AdminState>,
    Path((company, user, role)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let role = OperatorRole::parse(&role).ok_or(Error::NotFound)?;
    let revoking = state.clone();
    apply(
        &state,
        (&company, &headers, &body),
        (role, REVOKE),
        |operator, sent: Revoking| async move {
            let Ok(user) = UserId::parse(user) else {
                return refused(StatusCode::CONFLICT, "not_granted", None);
            };
            let reason = reason_of(&sent)?;
            let taken = revoking
                .operators
                .revoke(
                    &operator.tenant,
                    &user,
                    role,
                    operator.user.as_str(),
                    &reason,
                    (revoking.clock)(),
                )
                .await
                .map_err(Error::Store)?;
            if !taken {
                return refused(StatusCode::CONFLICT, "not_granted", Some(user));
            }
            Ok(Made {
                status: StatusCode::OK,
                body: serde_json::to_string(&Revoked {
                    user: user.as_str(),
                    role: role.name(),
                    revoked: true,
                })
                .map_err(|_| Error::Internal)?,
                shown: None,
                user: Some(user),
            })
        },
    )
    .await
}

/// The grant a cursor `<user>.<role>` names.
fn anchor(after: &str) -> Result<(UserId, OperatorRole)> {
    let (user, role) = after.rsplit_once('.').ok_or(Error::Invalid)?;
    let user = UserId::parse(user).map_err(|_| Error::Invalid)?;
    let role = OperatorRole::parse(role).ok_or(Error::Invalid)?;
    Ok((user, role))
}

/// `grant` as the console shows it.
fn shown(grant: OperatorGrant) -> Shown {
    Shown {
        user: grant.user.as_str().to_owned(),
        role: grant.role.name(),
        granted_by: grant.granted_by,
        granted_at: grant.granted_at.unix_secs(),
        expires_at: grant.expires_at.map(Timestamp::unix_secs),
        reason: grant.reason,
    }
}

/// A change not made, for the reason `code` names.
fn refused(status: StatusCode, code: &'static str, user: Option<UserId>) -> Result<Made> {
    let message = match code {
        "user_not_found" => "this company has no such account",
        "account_disabled" => "the account is disabled; enable it first",
        "self_grant" => "no operator grants a role to themselves; another operator must",
        "above_ceiling" => "this company's users may not hold this role",
        _ => "the account does not hold this role",
    };
    Ok(Made {
        status,
        body: serde_json::to_string(&Refusal { code, message }).map_err(|_| Error::Internal)?,
        shown: None,
        user,
    })
}
