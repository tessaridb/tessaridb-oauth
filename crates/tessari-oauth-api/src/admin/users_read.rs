//! A company's user accounts read in its console by an operator holding `users`: a page at a time in id order behind
//! a cursor and with no total, or the one account an exact address names. Every address is masked; showing one whole
//! is a separate, recorded act.

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::{USER_PAGE_DEFAULT, USER_PAGE_MAX};
use tessari_oauth_core::subject::SubjectSector;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::UserAccount;
use tessari_oauth_types::{EmailAddress, Sector, UserId};

use super::AdminState;
use super::change::{Reasoned, Refusal, reason_of};
use super::operator::{Operator, from_console, signed_in};
use crate::{Error, Result};

/// The read the routes below name when it is refused.
const READ: &str = "users.read";
/// The act of showing one address whole.
const REVEAL: &str = "users.reveal_email";

/// Why an address is to be shown whole.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reveal {
    reason: String,
}

impl Reasoned for Reveal {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// One address, whole.
#[derive(Serialize)]
struct Revealed<'a> {
    user: &'a str,
    email: &'a str,
}

/// What a list asks for: a page after an account, or the account of one exact address.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Listing {
    after: Option<String>,
    limit: Option<u32>,
    email: Option<String>,
}

/// One account as the console shows it.
#[derive(Serialize)]
struct Shown {
    user: String,
    email: String,
    email_verified: bool,
    status: &'static str,
}

/// A page of accounts, and the cursor of the next one when this one is full.
#[derive(Serialize)]
struct Page {
    users: Vec<Shown>,
    next: Option<String>,
}

/// The company's accounts: a page after `after`, or the account `email` names.
pub(super) async fn list(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    listing: std::result::Result<Query<Listing>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Users, READ).await?;
    let Query(listing) = listing.map_err(|_| Error::Invalid)?;
    let tenant = &operator.tenant;
    if let Some(email) = listing.email {
        if listing.after.is_some() || listing.limit.is_some() {
            return Err(Error::Invalid);
        }
        let email = EmailAddress::parse(email.as_str()).map_err(|_| Error::Invalid)?;
        let found = state
            .users
            .find_by_email(tenant, &email)
            .await
            .map_err(Error::Store)?;
        shown_to(&state, &operator, usize::from(found.is_some())).await?;
        let users = found.iter().map(shown).collect();
        return Ok(Json(Page { users, next: None }).into_response());
    }
    let limit = listing.limit.unwrap_or(USER_PAGE_DEFAULT);
    if !(1..=USER_PAGE_MAX).contains(&limit) {
        return Err(Error::Invalid);
    }
    let after = listing
        .after
        .map(|after| UserId::parse(after).map_err(|_| Error::Invalid))
        .transpose()?;
    let accounts = state
        .users
        .page(tenant, after.as_ref(), limit)
        .await
        .map_err(Error::Store)?;
    let full = u32::try_from(accounts.len()).is_ok_and(|count| count == limit);
    let next = accounts
        .last()
        .filter(|_| full)
        .map(|account| account.user.as_str().to_owned());
    shown_to(&state, &operator, accounts.len()).await?;
    let users = accounts.iter().map(shown).collect();
    Ok(Json(Page { users, next }).into_response())
}

/// A pairwise subject as a client of a sector knows a person.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Subject {
    sector: String,
    sub: String,
}

/// The company's account that the subject `sub` stands for in `sector`, shown as [`one`] shows it: how a program
/// that knows a person only by the subject its sector's clients were given finds the account to act on.
pub(super) async fn by_subject(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    asked: std::result::Result<Query<Subject>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Users, READ).await?;
    let Query(asked) = asked.map_err(|_| Error::Invalid)?;
    let sector = Sector::parse(asked.sector).map_err(|_| Error::Invalid)?;
    // A pairwise subject is 43 base64url characters; anything far longer is not one, and is not looked up.
    if asked.sub.is_empty() || asked.sub.len() > 128 {
        return Err(Error::Invalid);
    }
    let user = state
        .subjects
        .user_of(&operator.tenant, &SubjectSector::Named(sector), &asked.sub)
        .await
        .map_err(Error::Store)?;
    let found = match user {
        Some(user) => state
            .users
            .find(&operator.tenant, &user)
            .await
            .map_err(Error::Store)?,
        None => None,
    };
    let Some(account) = found else {
        return Ok(missing());
    };
    shown_to(&state, &operator, 1).await?;
    Ok(Json(shown(&account)).into_response())
}

/// The company's account `user`.
pub(super) async fn one(
    State(state): State<AdminState>,
    Path((company, user)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Users, READ).await?;
    let found = match UserId::parse(user) {
        Ok(user) => state
            .users
            .find(&operator.tenant, &user)
            .await
            .map_err(Error::Store)?,
        Err(_) => None,
    };
    let Some(account) = found else {
        return Ok(missing());
    };
    shown_to(&state, &operator, 1).await?;
    Ok(Json(shown(&account)).into_response())
}

/// Show the address of the company's account `user` whole, recorded with the operator's reason before it is shown.
pub(super) async fn reveal(
    State(state): State<AdminState>,
    Path((company, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    from_console(&state, &headers)?;
    let operator = signed_in(&state, &company, &headers).await?;
    operator
        .require(&state, OperatorRole::Users, REVEAL)
        .await?;
    // A service never sees what the console masks: it acts on accounts, not on the people behind them.
    operator.in_console(&state, REVEAL).await?;
    let sent: Reveal = serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
    let reason = reason_of(&sent)?;
    let found = match UserId::parse(user) {
        Ok(user) => state
            .users
            .find(&operator.tenant, &user)
            .await
            .map_err(Error::Store)?,
        Err(_) => None,
    };
    let Some(account) = found else {
        return Ok(missing());
    };
    // The record is the control: an address nobody could later see revealed is not shown.
    let event = AuditEvent {
        actor: Some(operator.actor.name()),
        user: Some(account.user.clone()),
        role: Some(OperatorRole::Users),
        action: Some(REVEAL.to_owned()),
        reason: Some(reason),
        ..AuditEvent::of(AuditKind::AdminAction)
    };
    state
        .audit
        .record(&operator.tenant, &event, (state.clock)())
        .await
        .map_err(Error::Store)?;
    shown_to(&state, &operator, 1).await?;
    Ok(Json(Revealed {
        user: account.user.as_str(),
        email: account.email.as_str(),
    })
    .into_response())
}

/// Count `accounts` shown to `operator` before they are answered, and log the read that takes the operator's count for
/// the hour to the number worth noticing (admin console reads are personal data).
async fn shown_to(state: &AdminState, operator: &Operator, accounts: usize) -> Result<()> {
    if accounts == 0 {
        return Ok(());
    }
    let accounts = u64::try_from(accounts).map_err(|_| Error::Internal)?;
    let reads = state
        .throttle
        .operator_read(&operator.tenant, &operator.actor, accounts, (state.clock)())
        .await
        .map_err(Error::Store)?;
    if reads.noticed {
        tracing::warn!(
            event = "operator_reads_high",
            tenant = operator.tenant.as_str(),
            operator = operator.actor.name(),
            accounts = reads.total,
            "an operator was shown more accounts this hour than is usual"
        );
    }
    Ok(())
}

/// The answer for an account the company does not have.
fn missing() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(Refusal {
            code: "user_not_found",
            message: "this company has no such account",
        }),
    )
        .into_response()
}

/// `account` with its address masked.
fn shown(account: &UserAccount) -> Shown {
    Shown {
        user: account.user.as_str().to_owned(),
        email: masked(&account.email),
        email_verified: account.email_verified,
        status: account.status.name(),
    }
}

/// `email` with all of its local part but the first character hidden: `k***@acme.example`.
pub(super) fn masked(email: &EmailAddress) -> String {
    let address = email.as_str();
    let (local, domain) = address.rsplit_once('@').unwrap_or((address, ""));
    let first: String = local.chars().take(1).collect();
    format!("{first}***@{domain}")
}
