//! The subject a sector's clients know one of the company's accounts by, read by an operator holding `users`: how a
//! program that keys its customers by that subject finds the customer behind an account it found by its address.
//! The subject is derived, never recorded, so a read leaves no trace a reverse lookup could later follow.

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_core::subject::SubjectSector;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{Sector, UserId};

use super::AdminState;
use super::operator::signed_in;
use super::users_read::{missing, shown_to};
use crate::{Error, Result};

/// The read the route names when it is refused.
const READ: &str = "users.read";

/// The sector whose subject is asked for.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Asked {
    sector: String,
}

/// An account and the subject the sector knows it by.
#[derive(Serialize)]
struct Known<'a> {
    user: &'a str,
    sector: &'a str,
    subject: String,
}

/// The subject `sector` knows the company's account `user` by.
pub(super) async fn subject(
    State(state): State<AdminState>,
    Path((company, user)): Path<(String, String)>,
    headers: HeaderMap,
    asked: std::result::Result<Query<Asked>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Users, READ).await?;
    let Query(asked) = asked.map_err(|_| Error::Invalid)?;
    let sector = Sector::parse(asked.sector).map_err(|_| Error::Invalid)?;
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
    let subject = state
        .subjects
        .derive(
            &operator.tenant,
            &state.kek,
            &SubjectSector::Named(sector.clone()),
            &account.user,
            (state.clock)(),
        )
        .await
        .map_err(Error::Store)?;
    shown_to(&state, &operator, 1).await?;
    Ok(Json(Known {
        user: account.user.as_str(),
        sector: sector.as_str(),
        subject,
    })
    .into_response())
}
