//! `POST /{tenant}/login/api/*`: the sign-in page's steps, each taken against the sign-in its browser holds.
//!
//! A browser's sign-in is found by the cookie `begin` set (a 256-bit value the server chose, so a value planted in
//! the browser beforehand names nothing), and every step re-reads it, applies the ceremony's own transition and
//! writes it back only if nothing moved it in between. An answer says only which step comes next, read from where
//! the ceremony stands, so an identifier that names no account is answered exactly as one that does. Bodies are
//! JSON, which a cross-site form cannot send, and the cookie is `SameSite=Lax`, which a cross-site POST does not
//! carry. No answer may be stored by a cache.
//!
//! The step that completes a sign-in takes it, so no other step can follow it, and opens the user's session at this
//! issuer under a cookie of its own whose value is drawn then: whatever the browser held before, a value planted in
//! it beforehand names no session. The sign-in cookie is cleared and the answer says where the pending
//! authorization continues.

mod begin;
mod consent;
mod factors;
mod identify;
mod passkey;
mod password;

pub(super) use begin::begin;
pub(super) use consent::{consent, decide};
pub(super) use factors::{recovery, totp};
pub(super) use identify::identify;
pub(super) use passkey::{passkey, passkey_options};
pub(super) use password::password;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_constants::{
    AUTHORIZE_RESUME_PATH, INTERACTION_TTL_SECS, LOGIN_COOKIE, SESSION_ABSOLUTE_SECS,
    SESSION_COOKIE,
};
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::ceremony::{Ceremony, CeremonyRefused, Stage};
use tessari_oauth_core::signin::SigninKey;
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{SessionSecret, SigninBinding, TenantId, Timestamp, UserId, base64url};

use crate::state::PublicState;
use crate::{Error, Result};

/// The longest cookie value read as a binding; the server's own are 43 characters.
const BINDING_MAX_LEN: usize = 128;

/// What every step answers.
#[derive(Serialize)]
struct Next {
    next: &'static str,
}

/// What the step that completes a sign-in answers.
#[derive(Serialize)]
struct Completed {
    next: &'static str,
    #[serde(rename = "continue")]
    continue_at: String,
}

/// The name of the step that follows `stage`.
const fn next(stage: Stage) -> &'static str {
    match stage {
        Stage::Identify => "identify",
        Stage::FirstFactor => "first_factor",
        Stage::SecondFactor => "second_factor",
        Stage::Complete => "complete",
    }
}

/// The answer to a step that left the sign-in at `stage`, setting `cookie` when given.
fn answer(stage: Stage, cookie: Option<HeaderValue>) -> Response {
    let mut response = (StatusCode::OK, Json(Next { next: next(stage) })).into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

/// The body of a step, or [`Error::Invalid`] when it is not the JSON the step reads.
fn body<T>(read: std::result::Result<Json<T>, JsonRejection>) -> Result<T> {
    read.map(|Json(body)| body).map_err(|_| Error::Invalid)
}

/// Whether `value` could be one of this server's ids or bindings: base64url, and short.
pub(super) fn well_formed(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= BINDING_MAX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The value of the request's cookie `name`, when it carries one that could be this server's.
pub(super) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(found, _)| *found == name)
        .map(|(_, value)| value)
        .filter(|value| well_formed(value))
}

/// The binding the request's sign-in cookie carries, or [`Error::SigninGone`] when there is none.
fn binding(headers: &HeaderMap) -> Result<SigninBinding> {
    cookie(headers, LOGIN_COOKIE)
        .map(SigninBinding::from_secret)
        .ok_or(Error::SigninGone)
}

/// The cookie that binds a sign-in to the browser `begin` answered.
fn binding_cookie(binding: &SigninBinding) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{LOGIN_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={INTERACTION_TTL_SECS}",
        binding.expose()
    ))
    .map_err(|_| Error::Internal)
}

/// The cookie that carries the session `secret` names.
fn session_cookie(secret: &SessionSecret) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_ABSOLUTE_SECS}",
        secret.expose()
    ))
    .map_err(|_| Error::Internal)
}

/// The cookie that clears the sign-in cookie once the sign-in is finished.
fn cleared_binding_cookie() -> Result<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{LOGIN_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .map_err(|_| Error::Internal)
}

/// Answer a step that left the sign-in `binding` holds in `tenant` at `stage`. Below `Complete` that is the next
/// step. At `Complete` the sign-in is taken, once, a session is opened for its user under a value drawn now, the
/// sign-in is recorded, and the browser is sent on to the authorization it was begun for at `issuer`.
async fn settled(
    state: &PublicState,
    tenant: &TenantId,
    issuer: &str,
    binding: &SigninBinding,
    stage: Stage,
) -> Result<Response> {
    if stage != Stage::Complete {
        return Ok(answer(stage, None));
    }
    let now = (state.clock)();
    let signin = state
        .signins
        .finish(tenant, binding, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SigninGone)?;
    let (user, _) = signin.ceremony.outcome().ok_or(Error::Internal)?;
    let drawn = random_secret().map_err(|_| Error::Internal)?;
    let secret = SessionSecret::from_secret(base64url::encode(&drawn));
    state
        .sessions
        .create(
            tenant,
            &secret,
            user,
            signin.ceremony.verified_methods(),
            now,
        )
        .await
        .map_err(Error::Store)?;
    tracing::info!(
        event = "signed_in",
        tenant = tenant.as_str(),
        "a sign-in completed and opened a session"
    );
    let event = AuditEvent {
        user: Some(user.clone()),
        ..AuditEvent::of(AuditKind::SignedIn)
    };
    record(state, tenant, &event, now).await;
    let completed = Completed {
        next: next(Stage::Complete),
        continue_at: format!(
            "{issuer}{AUTHORIZE_RESUME_PATH}?interaction={}",
            signin.interaction
        ),
    };
    let mut response = (StatusCode::OK, Json(completed)).into_response();
    let headers = response.headers_mut();
    headers.append(header::SET_COOKIE, session_cookie(&secret)?);
    headers.append(header::SET_COOKIE, cleared_binding_cookie()?);
    Ok(response)
}

/// Take one step of the sign-in `binding` holds in `tenant`: `transition` applied to where it stands, written back
/// only if nothing moved it since it was read, counted under `account` when given and under the key it already
/// holds otherwise. Answers the stage it reached.
async fn step(
    state: &PublicState,
    tenant: &TenantId,
    binding: &SigninBinding,
    account: Option<String>,
    transition: impl FnOnce(Ceremony) -> std::result::Result<Ceremony, CeremonyRefused>,
) -> Result<Stage> {
    let now = (state.clock)();
    let signin = state
        .signins
        .resume(tenant, binding, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SigninGone)?;
    let moved = transition(signin.ceremony).map_err(|_| Error::StepRefused)?;
    let written = state
        .signins
        .advance(
            tenant,
            binding,
            signin.revision,
            &moved,
            account.or(signin.account).as_deref(),
        )
        .await
        .map_err(Error::Store)?;
    if !written {
        return Err(Error::StepRefused);
    }
    Ok(moved.stage())
}

/// Refuse with the wait when any of `keys` is held at `now`; the same answer whichever key it is.
async fn unless_held(
    state: &PublicState,
    keys: &[(SigninKey, &str)],
    now: Timestamp,
) -> Result<()> {
    match state
        .throttle
        .signin_hold(keys, now)
        .await
        .map_err(Error::Store)?
    {
        Some(retry_after_secs) => Err(Error::Throttled { retry_after_secs }),
        None => Ok(()),
    }
}

/// Count a credential that proved nothing against `keys` at `now` and record it, `user` named when one was
/// identified; answers the one rejection every such step gives.
async fn rejected(
    state: &PublicState,
    tenant: &TenantId,
    keys: &[(SigninKey, &str)],
    user: Option<UserId>,
    now: Timestamp,
) -> Error {
    if let Err(failure) = state.throttle.signin_failed(keys, now).await {
        return Error::Store(failure);
    }
    tracing::warn!(
        event = "signin_rejected",
        tenant = tenant.as_str(),
        "a sign-in credential was rejected"
    );
    let event = AuditEvent {
        user,
        reason: Some("credentials_rejected".to_owned()),
        ..AuditEvent::of(AuditKind::Refused)
    };
    record(state, tenant, &event, now).await;
    Error::CredentialsRejected
}

/// Append `event` to `tenant`'s trail; a trail that cannot take it is logged, never the reason a step fails.
async fn record(state: &PublicState, tenant: &TenantId, event: &AuditEvent, now: Timestamp) {
    if let Err(failure) = state.audit.record(tenant, event, now).await {
        tracing::error!(
            event = "audit_unrecorded",
            tenant = tenant.as_str(),
            category = ?failure.category(),
            "a sign-in event could not be appended to the audit trail"
        );
    }
}

/// Record `method` as verified on the sign-in `binding` holds in `tenant` at `issuer`, forget the failures of the
/// identified address's key `account`, and answer where the sign-in stands.
async fn verified(
    state: &PublicState,
    (tenant, issuer): (&TenantId, &str),
    binding: &SigninBinding,
    account: &str,
    method: Method,
) -> Result<Response> {
    let stage = step(state, tenant, binding, None, |ceremony| {
        ceremony.verified(method)
    })
    .await?;
    forget(state, tenant, account).await;
    settled(state, tenant, issuer, binding, stage).await
}

/// Forget the failures of the identified address's key `account` once a step is taken. The step stands either way:
/// forgetting is housekeeping, failures left counted lapse with their window, and under a run of failures against
/// the same address the forget can keep losing to their counts, which must not turn a taken step into a refusal.
async fn forget(state: &PublicState, tenant: &TenantId, account: &str) {
    if let Err(failure) = state.throttle.signin_succeeded(account).await {
        tracing::warn!(
            event = "signin_failures_kept",
            tenant = tenant.as_str(),
            category = ?failure.category(),
            "a sign-in step was taken but its address's failures could not be forgotten"
        );
    }
}
