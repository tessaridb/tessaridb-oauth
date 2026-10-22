//! `POST /{tenant}/login/api/*`: the sign-in page's steps, each taken against the sign-in its browser holds.
//!
//! A browser's sign-in is found by the cookie `begin` set (a 256-bit value the server chose, so a value planted in
//! the browser beforehand names nothing), and every step re-reads it, applies the ceremony's own transition and
//! writes it back only if nothing moved it in between. An answer says only which step comes next, read from where
//! the ceremony stands, so an identifier that names no account is answered exactly as one that does. Bodies are
//! JSON, which a cross-site form cannot send, and the cookie is `SameSite=Lax`, which a cross-site POST does not
//! carry. No answer may be stored by a cache.

mod begin;
mod identify;

pub(super) use begin::begin;
pub(super) use identify::identify;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_constants::{INTERACTION_TTL_SECS, LOGIN_COOKIE};
use tessari_oauth_core::ceremony::{Ceremony, CeremonyRefused, Stage};
use tessari_oauth_types::{SigninBinding, TenantId};

use crate::state::PublicState;
use crate::{Error, Result};

/// The longest cookie value read as a binding; the server's own are 43 characters.
const BINDING_MAX_LEN: usize = 128;

/// What every step answers.
#[derive(Serialize)]
struct Next {
    next: &'static str,
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
fn well_formed(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= BINDING_MAX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The binding the request's sign-in cookie carries, or [`Error::SigninGone`] when there is none.
fn binding(headers: &HeaderMap) -> Result<SigninBinding> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == LOGIN_COOKIE)
        .map(|(_, value)| value)
        .filter(|value| well_formed(value))
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
