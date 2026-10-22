//! An enrolment code issued in the console by an operator holding `users`, for an active account that has never set a
//! password: the code is shown once, in the answer to the request that issued it, and kept only as its digest. A
//! repeat of that request is answered without it, and a new code replaces the one before.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::Serialize;
use tessari_oauth_constants::ENROLMENT_TTL_SECS;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::UserStatus;
use tessari_oauth_types::{EnrolmentCode, UserId};

use super::AdminState;
use super::change::{Made, Refusal, apply};
use super::signin::fresh;
use super::users::Move;
use crate::{Error, Result};

/// The change `POST .../api/users/{id}/enrolment` names.
const ENROL: &str = "users.enrol";

/// A code issued: for whom, the code when this is the one answer allowed to carry it, and for how long it enrols.
#[derive(Serialize)]
struct Issued<'a> {
    user: &'a str,
    code: Option<&'a str>,
    shown_once: bool,
    valid_secs: u64,
}

/// Issue the account `user` of `company` an enrolment code, replacing any earlier one.
pub(super) async fn enrol(
    State(state): State<AdminState>,
    Path((company, user)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let issuing = state.clone();
    apply(
        &state,
        (&company, &headers, &body),
        (OperatorRole::Users, ENROL),
        |operator, _: Move| async move {
            let tenant = &operator.tenant;
            let found = match UserId::parse(user) {
                Ok(user) => issuing
                    .users
                    .find(tenant, &user)
                    .await
                    .map_err(Error::Store)?,
                Err(_) => None,
            };
            let Some(account) = found else {
                return refused(StatusCode::NOT_FOUND, "user_not_found", None);
            };
            let user = account.user;
            if account.status == UserStatus::Disabled {
                return refused(StatusCode::CONFLICT, "account_disabled", Some(user));
            }
            // An enrolment sets a first password and never replaces one.
            let holds_password = issuing
                .users
                .password(tenant, &user)
                .await
                .map_err(Error::Store)?
                .is_some();
            if holds_password {
                return refused(StatusCode::CONFLICT, "already_enrolled", Some(user));
            }
            let code = EnrolmentCode::from_secret(fresh()?);
            issuing
                .enrolments
                .issue(
                    tenant,
                    &code,
                    &user,
                    operator.user.as_str(),
                    (issuing.clock)(),
                )
                .await
                .map_err(Error::Store)?;
            let kept = issued(&user, None)?;
            let shown = issued(&user, Some(code.expose()))?;
            Ok(Made {
                status: StatusCode::CREATED,
                body: kept,
                shown: Some(shown),
                user: Some(user),
            })
        },
    )
    .await
}

/// The answer for a code issued to `user`, carrying `code` only when it is the answer that shows it.
fn issued(user: &UserId, code: Option<&str>) -> Result<String> {
    serde_json::to_string(&Issued {
        user: user.as_str(),
        code,
        shown_once: true,
        valid_secs: ENROLMENT_TTL_SECS,
    })
    .map_err(|_| Error::Internal)
}

/// A code not issued, for the reason `code` names.
fn refused(status: StatusCode, code: &'static str, user: Option<UserId>) -> Result<Made> {
    let message = match code {
        "user_not_found" => "this company has no such account",
        "account_disabled" => "the account is disabled; enable it first",
        _ => "the account already has a password; an enrolment code never replaces one",
    };
    Ok(Made {
        status,
        body: serde_json::to_string(&Refusal { code, message }).map_err(|_| Error::Internal)?,
        shown: None,
        user,
    })
}
