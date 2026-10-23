//! A company's groups read in its console by an operator holding `users`: a page of groups at a time in id order
//! behind a cursor and with no total, one group with the roles it carries, and a page of its members.

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::{GROUP_PAGE_DEFAULT, GROUP_PAGE_MAX};
use tessari_oauth_storage::groups::{Group, Membership};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{GroupId, UserId};

use super::AdminState;
use super::change::Refusal;
use super::operator::signed_in;
use crate::{Error, Result};

/// The read the routes below name when it is refused.
const READ: &str = "groups.read";

/// What a list asks for: a page after a group, or after a member.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Listing {
    after: Option<String>,
    limit: Option<u32>,
}

/// One group as the console shows it.
#[derive(Serialize)]
pub(super) struct Shown {
    group: String,
    description: String,
    roles: Vec<String>,
    created_at: u64,
}

/// A page of groups, and the cursor of the next one when this one is full.
#[derive(Serialize)]
struct Page {
    groups: Vec<Shown>,
    next: Option<String>,
}

/// One member as the console shows it.
#[derive(Serialize)]
struct Member {
    user: String,
    added_at: u64,
    added_by: String,
}

/// A page of members, and the cursor of the next one when this one is full.
#[derive(Serialize)]
struct Members {
    members: Vec<Member>,
    next: Option<String>,
}

/// The page size `listing` asks for, within its bounds.
fn limit_of(listing: &Listing) -> Result<u32> {
    let limit = listing.limit.unwrap_or(GROUP_PAGE_DEFAULT);
    if (1..=GROUP_PAGE_MAX).contains(&limit) {
        Ok(limit)
    } else {
        Err(Error::Invalid)
    }
}

/// The cursor of the page after `items`, when `items` filled a page of `limit`.
fn next_of<T>(items: &[T], limit: u32, cursor: impl Fn(&T) -> String) -> Option<String> {
    let full = u32::try_from(items.len()).is_ok_and(|count| count == limit);
    items.last().filter(|_| full).map(cursor)
}

/// The company's groups, a page after `after`.
pub(super) async fn list(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    listing: std::result::Result<Query<Listing>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Users, READ).await?;
    let Query(listing) = listing.map_err(|_| Error::Invalid)?;
    let limit = limit_of(&listing)?;
    let after = listing
        .after
        .map(|after| GroupId::parse(after).map_err(|_| Error::Invalid))
        .transpose()?;
    let groups = state
        .groups
        .page(&operator.tenant, after.as_ref(), limit)
        .await
        .map_err(Error::Store)?;
    let next = next_of(&groups, limit, |group| group.id.as_str().to_owned());
    let groups = groups.iter().map(shown).collect();
    Ok(Json(Page { groups, next }).into_response())
}

/// The company's group `group`.
pub(super) async fn one(
    State(state): State<AdminState>,
    Path((company, group)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Users, READ).await?;
    let found = match GroupId::parse(group) {
        Ok(group) => state
            .groups
            .find(&operator.tenant, &group)
            .await
            .map_err(Error::Store)?,
        Err(_) => None,
    };
    Ok(found.map_or_else(missing, |group| Json(shown(&group)).into_response()))
}

/// The members of the company's group `group`, a page after `after`.
pub(super) async fn members(
    State(state): State<AdminState>,
    Path((company, group)): Path<(String, String)>,
    headers: HeaderMap,
    listing: std::result::Result<Query<Listing>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Users, READ).await?;
    let Query(listing) = listing.map_err(|_| Error::Invalid)?;
    let limit = limit_of(&listing)?;
    let Ok(group) = GroupId::parse(group) else {
        return Ok(missing());
    };
    let after = listing
        .after
        .map(|after| UserId::parse(after).map_err(|_| Error::Invalid))
        .transpose()?;
    if state
        .groups
        .find(&operator.tenant, &group)
        .await
        .map_err(Error::Store)?
        .is_none()
    {
        return Ok(missing());
    }
    let held = state
        .groups
        .members(&operator.tenant, &group, after.as_ref(), limit)
        .await
        .map_err(Error::Store)?;
    let next = next_of(&held, limit, |membership| {
        membership.user.as_str().to_owned()
    });
    let members = held.iter().map(member).collect();
    Ok(Json(Members { members, next }).into_response())
}

/// The answer for a group the company does not have.
pub(super) fn missing() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(Refusal {
            code: "group_not_found",
            message: "this company has no such group",
        }),
    )
        .into_response()
}

/// `group` as the console shows it.
pub(super) fn shown(group: &Group) -> Shown {
    Shown {
        group: group.id.as_str().to_owned(),
        description: group.description.clone(),
        roles: group
            .roles
            .iter()
            .map(|role| role.as_str().to_owned())
            .collect(),
        created_at: group.created_at.unix_secs(),
    }
}

fn member(membership: &Membership) -> Member {
    Member {
        user: membership.user.as_str().to_owned(),
        added_at: membership.added_at.unix_secs(),
        added_by: membership.added_by.clone(),
    }
}
