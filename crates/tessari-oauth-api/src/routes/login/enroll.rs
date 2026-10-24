//! `POST /{tenant}/login/api/enroll`: a user an operator created sets a first password with the code the operator
//! handed them.
//!
//! A code that was never issued, was spent, was replaced or has lapsed gets one answer, so the route says nothing about
//! which codes exist. The code is spent only once the password is accepted, so a refused password can be tried again;
//! an account that already has a password is refused and keeps it, because an enrolment code is not a way to reset
//! one. The password meets the rules for an account whose password is its only factor. No session is opened: the
//! user signs in as anyone does. With a relay configured a link that verifies the address is mailed to it. The value
//! is never logged, recorded or echoed.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tessari_oauth_constants::CURRENT_PEPPER;
use tessari_oauth_core::password::{Usage, accept};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::users::StoredPassword;
use tessari_oauth_types::EnrolmentCode;

use super::{body, record, send_verification};
use crate::routes::breached::screened;
use crate::state::PublicState;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(in crate::routes) struct Enrolment {
    code: String,
    password: String,
}

pub(in crate::routes) async fn enroll(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    read: std::result::Result<Json<Enrolment>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let Enrolment { code, password } = body(read)?;
    let now = (state.clock)();
    let code = EnrolmentCode::from_secret(code);
    let user = state
        .enrolments
        .find(&tenant, &code)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::CodeRejected)?;
    if state
        .users
        .password(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .is_some()
    {
        return Err(Error::AlreadyEnrolled);
    }
    // A code names an account that existed when it was issued, and accounts are never removed.
    let account = state
        .users
        .find(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Internal)?;
    let address = account.email.as_str();
    let local = address.split('@').next().unwrap_or(address);
    let accepted = accept(
        &password,
        Usage::Alone,
        |_| false,
        &[address, local, tenant.as_str()],
    )
    .map_err(Error::PasswordRejected)?;
    screened(&state, &accepted).await?;
    let hash = state
        .passwords
        .hash(&accepted)
        .await
        .map_err(|_| Error::Internal)?;
    // Two requests with one code both get here; the delete lets one of them through.
    let spent = state
        .enrolments
        .redeem(&tenant, &code)
        .await
        .map_err(Error::Store)?;
    if spent.as_ref() != Some(&user) {
        return Err(Error::CodeRejected);
    }
    state
        .users
        .set_password(
            &tenant,
            &user,
            &StoredPassword {
                hash,
                pepper: CURRENT_PEPPER,
            },
            now,
        )
        .await
        .map_err(Error::Store)?;
    // The operator typed the address; nothing yet shows the user reads it, so a link goes to it.
    if state.mail
        && let Err(failure) =
            send_verification(&state, &tenant, &issuer, &user, &account.email, now).await
    {
        tracing::warn!(
            event = "verification_unqueued",
            tenant = tenant.as_str(),
            %failure,
            "a verification link could not be queued; the enrolment stands"
        );
    }
    let event = AuditEvent {
        user: Some(user),
        reason: Some("enrolled".to_owned()),
        ..AuditEvent::of(AuditKind::FactorChanged)
    };
    record(&state, &tenant, &event, now).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}
