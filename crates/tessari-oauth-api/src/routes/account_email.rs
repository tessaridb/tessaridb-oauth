//! `POST /{tenant}/account/api/me/email`: the signed-in user asks to change the address their account signs in with.
//!
//! It needs a session that may change the account's factors (a recent sign-in at the account's level) and a relay.
//! The account's own address answers `204` and sends nothing. Any other address answers `202` whether or not another
//! account holds it, and does the same store work for both: a change held for a day, a mail to the new address and a
//! mail to the old one. A free address gets a link that confirms the change; a held one gets a notice that somebody
//! tried to use it, and its change can never be confirmed. The old address always gets a link that cancels the
//! change until it takes effect. Values are never logged, recorded or echoed.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tessari_oauth_constants::LOGIN_PATH;
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::email_changes::Addresses;
use tessari_oauth_storage::outbox::NewMail;
use tessari_oauth_types::{EmailAddress, TenantId, Timestamp, UserId, VerifyToken, base64url};

use super::account_factors::may_change;
use super::login::{body, record, signed_in};
use crate::state::PublicState;
use crate::{Error, Result};

/// The subject of the mail to the new address, free or held.
const NEW_SUBJECT: &str = "Confirm your new sign-in address";

/// The subject of the mail to the old address.
const OLD_SUBJECT: &str = "Your sign-in address is changing";

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
    let to_new = if held {
        taken_notice(&issuer, &addresses.new)
    } else {
        confirm_mail(&issuer, &addresses.new, &confirm)
    };
    let to_old = cancel_mail(&issuer, &addresses, &cancel);
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

fn fresh_token() -> Result<VerifyToken> {
    Ok(VerifyToken::from_secret(base64url::encode(
        &random_secret().map_err(|_| Error::Internal)?,
    )))
}

/// The mail that lets the new address confirm the change.
fn confirm_mail(issuer: &str, new: &EmailAddress, confirm: &VerifyToken) -> NewMail {
    let link = format!("{issuer}{LOGIN_PATH}/email#confirm={}", confirm.expose());
    NewMail {
        to: Some(new.clone()),
        subject: NEW_SUBJECT.to_owned(),
        text: format!(
            "Someone asked to sign in to an account at {issuer} with this address instead of the one it uses now.\n\n\
             To confirm it, open this link within 24 hours:\n{link}\n\n\
             The change takes effect a day after it was asked for, unless it is cancelled from the old address.\n\
             If you did not ask, ignore this mail; nothing changes.\n"
        ),
    }
}

/// The mail to a new address another account already signs in with: nothing it can confirm.
fn taken_notice(issuer: &str, new: &EmailAddress) -> NewMail {
    NewMail {
        to: Some(new.clone()),
        subject: NEW_SUBJECT.to_owned(),
        text: format!(
            "Someone asked to sign in to another account at {issuer} with this address.\n\n\
             This address already signs in to an account there, so nothing changes and it stays with that account.\n\
             If you did not expect this, you can ignore it.\n"
        ),
    }
}

/// The mail that lets the old address cancel the change until it takes effect.
fn cancel_mail(issuer: &str, addresses: &Addresses, cancel: &VerifyToken) -> NewMail {
    let link = format!("{issuer}{LOGIN_PATH}/email#cancel={}", cancel.expose());
    let new = addresses.new.as_str();
    NewMail {
        to: Some(addresses.old.clone()),
        subject: OLD_SUBJECT.to_owned(),
        text: format!(
            "Someone signed in to your account at {issuer} asked to change the address it signs in with to {new}.\n\n\
             The change takes effect 24 hours after it was asked for, once the new address confirms it.\n\
             If you did not ask, cancel it with this link before then, and change your password:\n{link}\n"
        ),
    }
}

async fn recorded(state: &PublicState, tenant: &TenantId, user: &UserId, now: Timestamp) {
    let event = AuditEvent {
        user: Some(user.clone()),
        reason: Some("requested".to_owned()),
        ..AuditEvent::of(AuditKind::AddressChanged)
    };
    record(state, tenant, &event, now).await;
}
