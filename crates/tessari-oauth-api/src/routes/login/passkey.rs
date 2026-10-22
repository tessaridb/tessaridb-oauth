//! `POST /{tenant}/login/api/passkey/options`: what the browser needs to ask an authenticator for a passkey.
//!
//! Each ask draws a fresh 256-bit challenge, kept for one assertion for its lifetime. The relying party is the
//! issuer's host, so a passkey made for this server works for every tenant it serves at that host and for no other
//! site. The answer lists no credentials: a list for an identified address would say whether it has an account
//! with passkeys, so the browser offers the passkeys it holds for this host and the step identifies the account
//! from the one chosen. Verification of the user is required where the passkey is the whole sign-in, and preferred
//! where it stands as a second factor.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_constants::WEBAUTHN_CHALLENGE_TTL_SECS;
use tessari_oauth_core::ceremony::Stage;
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::passkeys::Ceremony;
use tessari_oauth_types::base64url;

use super::binding;
use crate::state::PublicState;
use crate::{Error, Result};

/// What the browser passes to `navigator.credentials.get`.
#[derive(Serialize)]
struct Options {
    challenge: String,
    rp_id: String,
    user_verification: &'static str,
    timeout_ms: u64,
}

pub(in crate::routes) async fn passkey_options(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let rp_id = relying_party(issuer)?.0;
    let binding = binding(&headers)?;
    let now = (state.clock)();
    let signin = state
        .signins
        .resume(&tenant, &binding, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SigninGone)?;
    let user_verification = match signin.ceremony.stage() {
        Stage::Identify | Stage::FirstFactor => "required",
        Stage::SecondFactor => "preferred",
        Stage::Complete => return Err(Error::StepRefused),
    };
    let challenge = random_secret().map_err(|_| Error::Internal)?;
    state
        .passkeys
        .issue_challenge(&tenant, &challenge, Ceremony::Assertion, None, now)
        .await
        .map_err(Error::Store)?;
    let timeout_ms = WEBAUTHN_CHALLENGE_TTL_SECS
        .checked_mul(1000)
        .ok_or(Error::Internal)?;
    let options = Options {
        challenge: base64url::encode(&challenge),
        rp_id,
        user_verification,
        timeout_ms,
    };
    Ok((StatusCode::OK, Json(options)).into_response())
}

/// The relying-party id and the origin a passkey for `issuer` is made for: its host, and its scheme, host and port.
fn relying_party(issuer: &str) -> Result<(String, String)> {
    let url = url::Url::parse(issuer).map_err(|_| Error::Internal)?;
    let host = url.host_str().ok_or(Error::Internal)?.to_owned();
    Ok((host, url.origin().ascii_serialization()))
}
