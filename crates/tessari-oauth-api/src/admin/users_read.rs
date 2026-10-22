//! A company's user accounts read in its console by an operator holding `users`: a page at a time in id order behind
//! a cursor and with no total, or the one account an exact address names. Every address is masked; showing one whole
//! is a separate, recorded act.

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::{USER_PAGE_DEFAULT, USER_PAGE_MAX};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::UserAccount;
use tessari_oauth_types::{EmailAddress, UserId};

use super::AdminState;
use super::change::Refusal;
use super::operator::signed_in;
use crate::{Error, Result};

/// The read the routes below name when it is refused.
const READ: &str = "users.read";

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
    let users = accounts.iter().map(shown).collect();
    Ok(Json(Page { users, next }).into_response())
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
    match found {
        Some(account) => Ok(Json(shown(&account)).into_response()),
        None => Ok((
            axum::http::StatusCode::NOT_FOUND,
            Json(Refusal {
                code: "user_not_found",
                message: "this company has no such account",
            }),
        )
            .into_response()),
    }
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
fn masked(email: &EmailAddress) -> String {
    let address = email.as_str();
    let (local, domain) = address.rsplit_once('@').unwrap_or((address, ""));
    let first: String = local.chars().take(1).collect();
    format!("{first}***@{domain}")
}
