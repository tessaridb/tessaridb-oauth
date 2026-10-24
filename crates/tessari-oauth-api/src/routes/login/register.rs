//! `GET /{tenant}/login/api/registration` and `POST .../register`: whether the company lets people open their own
//! account, and a request to open one for an address.
//!
//! The policy is not secret, so a closed company answers `404` and an open one names no domain. An open company answers
//! `202` for every address it accepts, whatever account the address has, and the mailbox learns the rest: an address
//! with no account gets a new account and a link that sets its first password; an account that never set one gets a
//! new link, which replaces the earlier one; an account that signs in gets a notice and no link; a disabled account
//! gets nothing, sent as a mail with no recipient that the worker drops. No account is ever said to be taken to the
//! requester. An address at a domain the company does not open accounts for is refused, and the refusal is about the
//! domain, so it is the same for every address there. Each address and each source has a budget, counted for every
//! address alike, so the budgets say nothing about accounts either. Opening an account sets no password, opens no
//! session and leaves its address unverified until the address's own link is used.

use std::num::NonZeroU64;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::{
    LOGIN_PATH, REGISTRATION_ADDRESS_LIMIT, REGISTRATION_SOURCE_LIMIT, REGISTRATION_WINDOW_SECS,
};
use tessari_oauth_core::mail_template::{MailKind, Placeholder};
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::throttle::{Admission, Limit};
use tessari_oauth_storage::users::{Registered, UserAccount, UserStatus};
use tessari_oauth_types::{EmailAddress, EnrolmentCode, TenantId, Timestamp, UserId, base64url};

use super::{body, record};
use crate::routes::mail::compose;
use crate::state::PublicState;
use crate::throttle::ClientAddress;
use crate::{Error, Result};

/// The budget of registrations asked for one address.
const ADDRESS_GROUP: &str = "register-address";

/// The budget of registrations asked from one source.
const SOURCE_GROUP: &str = "register-source";

/// Who an enrolment code issued here is recorded as issued by.
const ISSUED_BY: &str = "self-registration";

#[derive(Deserialize)]
pub(in crate::routes) struct RegistrationRequest {
    email: String,
}

#[derive(Serialize)]
struct Registration {
    open: bool,
}

/// What the address's mailbox was sent, as the audit trail says it.
enum Sent {
    Created,
    CodeRenewed,
    ExistingNotified,
    Disabled,
}

impl Sent {
    const fn reason(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::CodeRenewed => "code_renewed",
            Self::ExistingNotified => "existing_notified",
            Self::Disabled => "disabled",
        }
    }
}

pub(in crate::routes) async fn registration(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let (policy, _) = state
        .policies
        .registration(&tenant)
        .await
        .map_err(Error::Store)?;
    Ok(Json(Registration {
        open: policy.is_open(),
    })
    .into_response())
}

pub(in crate::routes) async fn register(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    Extension(ClientAddress(source)): Extension<ClientAddress>,
    read: std::result::Result<Json<RegistrationRequest>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let RegistrationRequest { email } = body(read)?;
    let (policy, _) = state
        .policies
        .registration(&tenant)
        .await
        .map_err(Error::Store)?;
    if !policy.is_open() {
        return Err(Error::NotFound);
    }
    if !state.mail {
        return Err(Error::MailUnavailable);
    }
    let address = EmailAddress::parse(&email).map_err(|_| Error::EmailRejected)?;
    if !policy.admits(address.as_str()) {
        return Err(Error::AddressNotAccepted);
    }
    let now = (state.clock)();
    let keyed = state
        .passwords
        .signin_keys()
        .account(tenant.as_str(), address.as_str());
    spend(
        &state,
        ADDRESS_GROUP,
        &keyed,
        REGISTRATION_ADDRESS_LIMIT,
        now,
    )
    .await?;
    let from = format!("{}/{source}", tenant.as_str());
    spend(&state, SOURCE_GROUP, &from, REGISTRATION_SOURCE_LIMIT, now).await?;

    let (account, created) = match account(&state, &tenant, &address, now).await? {
        Some(found) => found,
        // Opened between the lookup and the write by another request for the same address: read it as found.
        None => (found(&state, &tenant, &address).await?, false),
    };
    let (sent, kind, to, link) = if account.status == UserStatus::Disabled {
        (Sent::Disabled, MailKind::RegistrationExisting, None, None)
    } else if holds_password(&state, &tenant, &account.user).await? {
        (
            Sent::ExistingNotified,
            MailKind::RegistrationExisting,
            Some(address),
            None,
        )
    } else {
        let code = EnrolmentCode::from_secret(base64url::encode(
            &random_secret().map_err(|_| Error::Internal)?,
        ));
        state
            .enrolments
            .issue(&tenant, &code, &account.user, ISSUED_BY, now)
            .await
            .map_err(Error::Store)?;
        let link = format!("{issuer}{LOGIN_PATH}/enrol#code={}", code.expose());
        let sent = if created {
            Sent::Created
        } else {
            Sent::CodeRenewed
        };
        (sent, MailKind::Registration, Some(address), Some(link))
    };
    let mut values = vec![(Placeholder::Issuer, &*issuer)];
    if let Some(link) = &link {
        values.push((Placeholder::Link, link.as_str()));
    }
    let mail = compose(&state.mail_templates, &tenant, kind, to, &values).await?;
    state
        .outbox
        .enqueue(&tenant, &state.kek, &mail)
        .await
        .map_err(Error::Store)?;
    let event = AuditEvent {
        user: Some(account.user),
        reason: Some(sent.reason().to_owned()),
        ..AuditEvent::of(AuditKind::AccountRegistered)
    };
    record(&state, &tenant, &event, now).await;
    Ok(StatusCode::ACCEPTED.into_response())
}

/// The account `address` signs in with and whether this request opened it; `None` when the address was taken
/// between the lookup and the write.
async fn account(
    state: &PublicState,
    tenant: &TenantId,
    address: &EmailAddress,
    now: Timestamp,
) -> Result<Option<(UserAccount, bool)>> {
    if let Some(existing) = state
        .users
        .find_by_email(tenant, address)
        .await
        .map_err(Error::Store)?
    {
        return Ok(Some((existing, false)));
    }
    match state
        .users
        .register(tenant, address, now)
        .await
        .map_err(Error::Store)?
    {
        Registered::Created(user) => Ok(Some((
            UserAccount {
                user,
                email: address.clone(),
                email_verified: false,
                status: UserStatus::Active,
            },
            true,
        ))),
        Registered::AddressTaken => Ok(None),
    }
}

async fn found(
    state: &PublicState,
    tenant: &TenantId,
    address: &EmailAddress,
) -> Result<UserAccount> {
    state
        .users
        .find_by_email(tenant, address)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Internal)
}

async fn holds_password(state: &PublicState, tenant: &TenantId, user: &UserId) -> Result<bool> {
    Ok(state
        .users
        .password(tenant, user)
        .await
        .map_err(Error::Store)?
        .is_some())
}

/// Spend one of the `requests` registrations `name` may ask for in `group` per window, refusing past the budget.
async fn spend(
    state: &PublicState,
    group: &str,
    name: &str,
    requests: u64,
    now: Timestamp,
) -> Result<()> {
    let limit = Limit {
        requests: NonZeroU64::new(requests).ok_or(Error::Internal)?,
        window_secs: NonZeroU64::new(REGISTRATION_WINDOW_SECS).ok_or(Error::Internal)?,
    };
    match state
        .throttle
        .admit(group, name, limit, now)
        .await
        .map_err(Error::Store)?
    {
        Admission::Admitted { .. } => Ok(()),
        Admission::Refused { retry_after_secs } => Err(Error::Throttled { retry_after_secs }),
    }
}
