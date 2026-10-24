//! `POST /{tenant}/account/api/me/email`: the signed-in user asks to change the address their account signs in with.
//!
//! It needs a session that may change the account's factors (a recent sign-in at the account's level) and a relay.
//! The account's own address answers `204` and sends nothing. Any other address answers `202` whether or not another
//! account holds it, and does the same store work for both: a change held for a day, a mail to the new address and a
//! mail to the old one. A free address gets a link that confirms the change; a held one gets a notice that somebody
//! tried to use it, and its change can never be confirmed. The old address always gets a link that cancels the
//! change until it takes effect. An account may ask a few times an hour, since every request mails an address the
//! user typed. Values are never logged, recorded or echoed.

use std::num::NonZeroU64;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tessari_oauth_constants::{
    EMAIL_CHANGE_REQUEST_LIMIT, EMAIL_CHANGE_REQUEST_WINDOW_SECS, LOGIN_PATH,
};
use tessari_oauth_core::mail_template::{MailKind, Placeholder};
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::email_changes::Addresses;
use tessari_oauth_storage::throttle::{Admission, Limit};
use tessari_oauth_types::{EmailAddress, TenantId, Timestamp, UserId, VerifyToken, base64url};

use super::account_factors::may_change;
use super::login::{body, record, signed_in};
use super::mail::compose;
use crate::state::PublicState;
use crate::{Error, Result};

/// The throttle group an account's address-change requests are counted in.
const BUDGET_GROUP: &str = "address-change";

#[derive(Deserialize)]
pub(super) struct NewEmail {
    email: String,
}

pub(super) async fn request(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<NewEmail>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let NewEmail { email } = body(read)?;
    let now = (state.clock)();
    let asking = signed_in(&state, &tenant, &headers, now).await?;
    may_change(&state, &tenant, &asking, now).await?;
    if !state.mail {
        return Err(Error::MailUnavailable);
    }
    let new = EmailAddress::parse(&email).map_err(|_| Error::EmailRejected)?;
    // A session names an account that existed when it signed in, and accounts are never removed.
    let account = state
        .users
        .find(&tenant, &asking.user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Internal)?;
    if account.email == new {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    spend_budget(&state, &tenant, &asking.user, now).await?;
    let held = state
        .users
        .find_by_email(&tenant, &new)
        .await
        .map_err(Error::Store)?
        .is_some();
    let confirm = fresh_token()?;
    let cancel = fresh_token()?;
    let addresses = Addresses {
        old: account.email,
        new,
    };
    state
        .email_changes
        .issue(&tenant, (&confirm, &cancel), &asking.user, &addresses, now)
        .await
        .map_err(Error::Store)?;
    // Both branches read the wording once and queue two mails, so a held address costs what a free one costs.
    let issued = [(Placeholder::Issuer, issuer.as_ref())];
    let to_new = if held {
        compose(
            &state.mail_templates,
            &tenant,
            MailKind::EmailTaken,
            Some(addresses.new.clone()),
            &issued,
        )
        .await?
    } else {
        let link = format!("{issuer}{LOGIN_PATH}/email#confirm={}", confirm.expose());
        let values = [
            (Placeholder::Issuer, issuer.as_ref()),
            (Placeholder::Link, link.as_str()),
        ];
        compose(
            &state.mail_templates,
            &tenant,
            MailKind::EmailConfirm,
            Some(addresses.new.clone()),
            &values,
        )
        .await?
    };
    let cancel_link = format!("{issuer}{LOGIN_PATH}/email#cancel={}", cancel.expose());
    let to_old = compose(
        &state.mail_templates,
        &tenant,
        MailKind::EmailCancel,
        Some(addresses.old.clone()),
        &[
            (Placeholder::Issuer, issuer.as_ref()),
            (Placeholder::Link, cancel_link.as_str()),
            (Placeholder::NewAddress, addresses.new.as_str()),
        ],
    )
    .await?;
    for mail in [to_new, to_old] {
        state
            .outbox
            .enqueue(&tenant, &state.kek, &mail)
            .await
            .map_err(Error::Store)?;
    }
    recorded(&state, &tenant, &asking.user, now).await;
    Ok(StatusCode::ACCEPTED.into_response())
}

/// Spend one of the address changes `user` may ask for in this window, refusing past the budget: each request mails an
/// address the user typed.
async fn spend_budget(
    state: &PublicState,
    tenant: &TenantId,
    user: &UserId,
    now: Timestamp,
) -> Result<()> {
    let limit = Limit {
        requests: NonZeroU64::new(EMAIL_CHANGE_REQUEST_LIMIT).ok_or(Error::Internal)?,
        window_secs: NonZeroU64::new(EMAIL_CHANGE_REQUEST_WINDOW_SECS).ok_or(Error::Internal)?,
    };
    let account = format!("{}/{}", tenant.as_str(), user.as_str());
    let admission = state
        .throttle
        .admit(BUDGET_GROUP, &account, limit, now)
        .await
        .map_err(Error::Store)?;
    match admission {
        Admission::Admitted { .. } => Ok(()),
        Admission::Refused { retry_after_secs } => Err(Error::Throttled { retry_after_secs }),
    }
}

fn fresh_token() -> Result<VerifyToken> {
    Ok(VerifyToken::from_secret(base64url::encode(
        &random_secret().map_err(|_| Error::Internal)?,
    )))
}

async fn recorded(state: &PublicState, tenant: &TenantId, user: &UserId, now: Timestamp) {
    let event = AuditEvent {
        user: Some(user.clone()),
        reason: Some("requested".to_owned()),
        ..AuditEvent::of(AuditKind::AddressChanged)
    };
    record(state, tenant, &event, now).await;
}
