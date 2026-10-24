//! A company's groups changed in its console by an operator holding `users`: made, given the roles they carry,
//! given and relieved of members, and deleted with every membership. Each is a named change with a reason, made once
//! per `Idempotency-Key`, and every name in a request is read by the type the server keeps it as.

use std::collections::BTreeSet;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tessari_oauth_storage::groups::{GroupCreated, Joined, NewGroup};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{ErrorCategory, GroupId, GroupRole, UserId};

use super::AdminState;
use super::change::{Made, Reasoned, Refusal, apply};
use super::groups_read::shown;
use crate::{Error, Result};

/// The change `POST .../api/groups` names.
const CREATE: &str = "groups.create";
/// The change `POST .../api/groups/{group}/roles` names.
const SET_ROLES: &str = "groups.roles";
/// The change `POST .../api/groups/{group}/members` names.
const ADD_MEMBER: &str = "groups.members.add";
/// The change `POST .../api/groups/{group}/members/{user}/remove` names.
const REMOVE_MEMBER: &str = "groups.members.remove";
/// The change `POST .../api/groups/{group}/remove` names.
const REMOVE: &str = "groups.remove";

/// A group to make.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Making {
    group: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    roles: Vec<String>,
    reason: String,
}

/// The roles a group is to carry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Roles {
    roles: Vec<String>,
    reason: String,
}

/// A user to add.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Adding {
    user: String,
    reason: String,
}

/// A removal: why.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Removal {
    reason: String,
}

impl Reasoned for Making {
    fn reason(&self) -> &str {
        &self.reason
    }
}

impl Reasoned for Roles {
    fn reason(&self) -> &str {
        &self.reason
    }
}

impl Reasoned for Adding {
    fn reason(&self) -> &str {
        &self.reason
    }
}

impl Reasoned for Removal {
    fn reason(&self) -> &str {
        &self.reason
    }
}

/// A membership changed: of whom, in which group.
#[derive(Serialize)]
struct Moved<'a> {
    group: &'a str,
    user: &'a str,
}

/// A group deleted.
#[derive(Serialize)]
struct Removed<'a> {
    group: &'a str,
}

/// `raw` as a set of roles, or refused.
fn roles_of(raw: Vec<String>) -> Result<BTreeSet<GroupRole>> {
    raw.into_iter()
        .map(|role| GroupRole::parse(role).map_err(|_| Error::Invalid))
        .collect()
}

/// A path's group; one outside the grammar is no group of this company.
fn group_in(raw: &str) -> Option<GroupId> {
    GroupId::parse(raw).ok()
}

/// A refusal kept as the change's answer.
fn refused(status: StatusCode, code: &'static str, message: &'static str) -> Result<Made> {
    Ok(Made {
        status,
        body: serde_json::to_string(&Refusal { code, message }).map_err(|_| Error::Internal)?,
        shown: None,
        user: None,
    })
}

fn no_group() -> Result<Made> {
    refused(
        StatusCode::NOT_FOUND,
        "group_not_found",
        "this company has no such group",
    )
}

/// An answer kept as the change's answer.
fn made(status: StatusCode, body: &impl Serialize, user: Option<UserId>) -> Result<Made> {
    Ok(Made {
        status,
        body: serde_json::to_string(body).map_err(|_| Error::Internal)?,
        shown: None,
        user,
    })
}

/// A store failure that is a value the store refused, which the request sent.
fn from_store(failure: tessari_oauth_storage::Error) -> Error {
    if failure.category() == ErrorCategory::Validation {
        Error::Invalid
    } else {
        Error::Store(failure)
    }
}

/// Make the group the request describes in `company`.
pub(super) async fn create(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let groups = std::sync::Arc::clone(&state.groups);
    let now = (state.clock)();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, CREATE),
        |operator, sent: Making| async move {
            let group = NewGroup {
                id: GroupId::parse(sent.group).map_err(|_| Error::Invalid)?,
                description: sent.description,
                roles: roles_of(sent.roles)?,
            };
            match groups
                .create(&operator.tenant, &group, now)
                .await
                .map_err(from_store)?
            {
                GroupCreated::Created(group) => made(StatusCode::CREATED, &shown(&group), None),
                GroupCreated::Taken => refused(
                    StatusCode::CONFLICT,
                    "group_taken",
                    "this company already has a group with this id",
                ),
            }
        },
    )
    .await
}

/// Set the roles the group `group` of `company` carries.
pub(super) async fn set_roles(
    State(state): State<AdminState>,
    Path((company, group)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let groups = std::sync::Arc::clone(&state.groups);
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, SET_ROLES),
        |operator, sent: Roles| async move {
            let roles = roles_of(sent.roles)?;
            let Some(group) = group_in(&group) else {
                return no_group();
            };
            if !groups
                .set_roles(&operator.tenant, &group, &roles)
                .await
                .map_err(from_store)?
            {
                return no_group();
            }
            match groups
                .find(&operator.tenant, &group)
                .await
                .map_err(Error::Store)?
            {
                Some(found) => made(StatusCode::OK, &shown(&found), None),
                None => no_group(),
            }
        },
    )
    .await
}

/// Add the user the request names to the group `group` of `company`.
pub(super) async fn add_member(
    State(state): State<AdminState>,
    Path((company, group)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let moving = state.clone();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, ADD_MEMBER),
        |operator, sent: Adding| async move {
            let user = UserId::parse(sent.user).map_err(|_| Error::Invalid)?;
            let Some(group) = group_in(&group) else {
                return no_group();
            };
            let tenant = &operator.tenant;
            if moving
                .users
                .find(tenant, &user)
                .await
                .map_err(Error::Store)?
                .is_none()
            {
                return refused(
                    StatusCode::NOT_FOUND,
                    "user_not_found",
                    "this company has no such account",
                );
            }
            let now = (moving.clock)();
            match moving
                .groups
                .join(tenant, &group, &user, operator.user.as_str(), now)
                .await
                .map_err(Error::Store)?
            {
                Joined::Added => made(
                    StatusCode::OK,
                    &Moved {
                        group: group.as_str(),
                        user: user.as_str(),
                    },
                    Some(user.clone()),
                ),
                Joined::NoSuchGroup => no_group(),
                Joined::TooManyGroups => refused(
                    StatusCode::CONFLICT,
                    "too_many_groups",
                    "this account is in as many groups as one account may be",
                ),
            }
        },
    )
    .await
}

/// Take the user `user` out of the group `group` of `company`.
pub(super) async fn remove_member(
    State(state): State<AdminState>,
    Path((company, group, user)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let groups = std::sync::Arc::clone(&state.groups);
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, REMOVE_MEMBER),
        |operator, _: Removal| async move {
            let (Some(group), Ok(user)) = (group_in(&group), UserId::parse(user)) else {
                return no_member();
            };
            if !groups
                .leave(&operator.tenant, &group, &user)
                .await
                .map_err(Error::Store)?
            {
                return no_member();
            }
            made(
                StatusCode::OK,
                &Moved {
                    group: group.as_str(),
                    user: user.as_str(),
                },
                Some(user.clone()),
            )
        },
    )
    .await
}

fn no_member() -> Result<Made> {
    refused(
        StatusCode::NOT_FOUND,
        "member_not_found",
        "this account is not in this group",
    )
}

/// Delete the group `group` of `company` and every membership of it.
pub(super) async fn remove(
    State(state): State<AdminState>,
    Path((company, group)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let groups = std::sync::Arc::clone(&state.groups);
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, REMOVE),
        |operator, _: Removal| async move {
            let Some(group) = group_in(&group) else {
                return no_group();
            };
            if !groups
                .delete(&operator.tenant, &group)
                .await
                .map_err(Error::Store)?
            {
                return no_group();
            }
            made(
                StatusCode::OK,
                &Removed {
                    group: group.as_str(),
                },
                None,
            )
        },
    )
    .await
}
