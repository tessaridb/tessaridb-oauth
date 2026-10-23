//! `POST /{tenant}/login/api/reset` and `.../reset/complete`: a user who lost their password asks for a reset link by
//! mail, then chooses a new password with it.
//!
//! The request answers `202` for every address, known, unknown or malformed, and does the same store work for each:
//! a known address gets a token bound to its account and a mail carrying the link, any other a token bound to an
//! account that does not exist and a mail with no recipient, which the mail worker drops. No relay is ever reached
//! while the request is answered. Without a relay configured the request answers `503` for every address.
//!
//! The link carries the token in its fragment, which reaches neither this server's logs nor a `Referer`. Completing
//! sets the password only: second factors and passkeys stay, so a sign-in afterwards still asks for them. It ends
//! every session, revokes every refresh family, is recorded, and tells the account's address. A token that was never
//! issued, was spent, was replaced or has lapsed gets one answer. Values are never logged, recorded or echoed.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tessari_oauth_constants::{CURRENT_PEPPER, LOGIN_PATH};
use tessari_oauth_core::password::{Usage, accept};
use tessari_oauth_core::two_factor::asks_second_factor;
use tessari_oauth_infrastructure::custody::{random_secret, token_id};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::outbox::NewMail;
use tessari_oauth_storage::refresh::Holder;
use tessari_oauth_storage::users::StoredPassword;
use tessari_oauth_types::{EmailAddress, ResetToken, TenantId, Timestamp, UserId, base64url};

use super::{body, record};
use crate::routes::notice::{Change, notify};
use crate::state::PublicState;
use crate::{Error, Result};

/// The subject of every reset mail, known address or not.
const RESET_SUBJECT: &str = "Reset your password";

#[derive(Deserialize)]
pub(in crate::routes) struct ResetRequest {
    email: String,
}

#[derive(Deserialize)]
pub(in crate::routes) struct ResetCompletion {
    token: String,
    password: String,
}

pub(in crate::routes) async fn request_reset(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    read: std::result::Result<Json<ResetRequest>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let ResetRequest { email } = body(read)?;
    if !state.mail {
        return Err(Error::MailUnavailable);
    }
    let now = (state.clock)();
    let account = match EmailAddress::parse(&email) {
        Ok(address) => state
            .users
            .find_by_email(&tenant, &address)
            .await
            .map_err(Error::Store)?
            .map(|account| (account.user, address)),
        Err(_) => None,
    };
    // An address with no account costs what one with an account costs: a token for nobody, a mail for nobody.
    let (holder, to) = match account {
        Some((user, address)) => (user, Some(address)),
        None => (nobody()?, None),
    };
    let token = ResetToken::from_secret(base64url::encode(
        &random_secret().map_err(|_| Error::Internal)?,
    ));
    state
        .resets
        .issue(&tenant, &token, &holder, now)
        .await
        .map_err(Error::Store)?;
    let link = format!("{issuer}{LOGIN_PATH}/reset#token={}", token.expose());
    let mail = NewMail {
        to,
        subject: RESET_SUBJECT.to_owned(),
        text: format!(
            "Someone asked to reset the password of your account at {issuer}.\n\n\
             To choose a new password, open this link within 30 minutes:\n{link}\n\n\
             Your second factor and passkeys stay as they are.\n\
             If you did not ask, ignore this mail; your password does not change.\n"
        ),
    };
    state
        .outbox
        .enqueue(&tenant, &state.kek, &mail)
        .await
        .map_err(Error::Store)?;
    Ok(StatusCode::ACCEPTED.into_response())
}

/// An account id no account holds: the holder of a token issued for an address with no account.
fn nobody() -> Result<UserId> {
    let id = token_id().map_err(|_| Error::Internal)?;
    UserId::parse(format!("nobody-{id}")).map_err(|_| Error::Internal)
}

pub(in crate::routes) async fn complete_reset(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    read: std::result::Result<Json<ResetCompletion>, JsonRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let ResetCompletion { token, password } = body(read)?;
    let now = (state.clock)();
    let token = ResetToken::from_secret(token);
    let user = state
        .resets
        .find(&tenant, &token)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::CodeRejected)?;
    // A token for an address with no account names an account that does not exist.
    let account = state
        .users
        .find(&tenant, &user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::CodeRejected)?;
    let usage = usage(&state, &tenant, &user).await?;
    let address = account.email.as_str();
    let local = address.split('@').next().unwrap_or(address);
    let accepted = accept(
        &password,
        usage,
        |_| false,
        &[address, local, tenant.as_str()],
    )
    .map_err(Error::PasswordRejected)?;
    let hash = state
        .passwords
        .hash(&accepted)
        .await
        .map_err(|_| Error::Internal)?;
    // Two requests with one token both get here; the delete lets one of them through.
    let spent = state
        .resets
        .redeem(&tenant, &token)
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
    cascade(&state, &tenant, &user, now).await?;
    notify(&state, &tenant, &user, Change::PasswordReset).await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// How short the new password may be: shorter only where every sign-in also asks for the authenticator app's code.
async fn usage(state: &PublicState, tenant: &TenantId, user: &UserId) -> Result<Usage> {
    let summary = state
        .factors
        .summary(tenant, user)
        .await
        .map_err(Error::Store)?;
    let policy = state
        .policies
        .two_factor(tenant)
        .await
        .map_err(Error::Store)?;
    Ok(if asks_second_factor(policy, summary.totp) {
        Usage::WithinMfa
    } else {
        Usage::Alone
    })
}

/// After a reset: every session of `user` ends and every refresh family is revoked, since whoever held the old
/// password may have opened them; the change is recorded.
async fn cascade(
    state: &PublicState,
    tenant: &TenantId,
    user: &UserId,
    now: Timestamp,
) -> Result<()> {
    state
        .sessions
        .end_all(tenant, user, None, now)
        .await
        .map_err(Error::Store)?;
    let families = state
        .refresh
        .revoke_standing(
            tenant,
            &Holder::User(user),
            Change::PasswordReset.reason(),
            now,
        )
        .await
        .map_err(Error::Store)?;
    let event = AuditEvent {
        user: Some(user.clone()),
        reason: Some(Change::PasswordReset.reason().to_owned()),
        families: Some(u64::try_from(families).map_err(|_| Error::Internal)?),
        ..AuditEvent::of(AuditKind::FactorChanged)
    };
    record(state, tenant, &event, now).await;
    Ok(())
}
