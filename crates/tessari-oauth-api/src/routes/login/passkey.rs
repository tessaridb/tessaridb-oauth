//! `POST /{tenant}/login/api/passkey/options` and `POST /{tenant}/login/api/passkey`: a sign-in by passkey.
//!
//! Each ask draws a fresh 256-bit challenge, kept for one assertion for its lifetime. The relying party is the
//! issuer's host, so a passkey made for this server works for every tenant it serves at that host and for no other
//! site. The answer lists no credentials: a list for an identified address would say whether it has an account
//! with passkeys, so the browser offers the passkeys it holds for this host and the step identifies the account
//! from the one chosen. Verification of the user is required where the passkey is the whole sign-in, and preferred
//! where it stands as a second factor.
//!
//! The assertion names its challenge in its client data; the challenge is spent before anything is verified, so an
//! assertion is answered once. Every check is then the relying party's own: the credential is one this tenant holds,
//! the signature is by its key over this host's authenticator data and this origin's client data, and its counter,
//! where the authenticator keeps one, moved forward (a counter that did not is recorded as a suspected clone). A
//! passkey that verified its user is the whole sign-in and may identify the account; one identified first must be
//! that account's. Anything that proves nothing is one failure, answered as a wrong password is.

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::WEBAUTHN_CHALLENGE_TTL_SECS;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::ceremony::{Identity, Stage};
use tessari_oauth_core::signin::SigninKey;
use tessari_oauth_core::webauthn::{self, Expected};
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::passkeys::Ceremony;
use tessari_oauth_types::base64url;

use super::{binding, body, forget, record, rejected, settled, step, unless_held};
use crate::state::PublicState;
use crate::throttle::ClientAddress;
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
pub(in crate::routes) fn relying_party(issuer: &str) -> Result<(String, String)> {
    let url = url::Url::parse(issuer).map_err(|_| Error::Internal)?;
    let host = url.host_str().ok_or(Error::Internal)?.to_owned();
    Ok((host, url.origin().ascii_serialization()))
}

/// What the browser's `navigator.credentials.get` answered, each part base64url.
#[derive(Deserialize)]
pub(in crate::routes) struct Assertion {
    credential_id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

pub(in crate::routes) async fn passkey(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    Extension(ClientAddress(source)): Extension<ClientAddress>,
    headers: HeaderMap,
    read: std::result::Result<Json<Assertion>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let (rp_id, origin) = relying_party(issuer)?;
    let binding = binding(&headers)?;
    let assertion = body(read)?;
    let decode = |part: &str| base64url::decode(part).map_err(|_| Error::Invalid);
    let credential_id = decode(&assertion.credential_id)?;
    let client_data = decode(&assertion.client_data_json)?;
    let authenticator_data = decode(&assertion.authenticator_data)?;
    let signature = decode(&assertion.signature)?;
    let now = (state.clock)();
    let signin = state
        .signins
        .resume(&tenant, &binding, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SigninGone)?;
    let stage = signin.ceremony.stage();
    if stage == Stage::Complete {
        return Err(Error::StepRefused);
    }
    let identified = match signin.ceremony.identity() {
        Some(Identity::Known { user, .. }) => Some(user.clone()),
        _ => None,
    };
    let mut keys = vec![(SigninKey::Source, source.as_str())];
    if let Some(account) = &signin.account {
        keys.push((SigninKey::Account, account.as_str()));
    }
    unless_held(&state, &keys, now).await?;
    let challenge = match webauthn::challenge_of(&client_data) {
        Some(challenge) => state
            .passkeys
            .spend_challenge(&tenant, &challenge, Ceremony::Assertion, now)
            .await
            .map_err(Error::Store)?
            .map(|_| challenge),
        None => None,
    };
    let found = match &challenge {
        Some(_) => state
            .passkeys
            .passkey(&tenant, &credential_id)
            .await
            .map_err(Error::Store)?,
        None => None,
    };
    let (Some(challenge), Some(passkey)) = (challenge, found) else {
        return Err(rejected(&state, &tenant, &keys, identified, now).await);
    };
    // Where an account was named first, only its own passkey may follow; an address naming nobody has none.
    if stage != Stage::Identify && identified.as_ref() != Some(&passkey.user) {
        return Err(rejected(&state, &tenant, &keys, identified, now).await);
    }
    let expected = Expected {
        rp_id: &rp_id,
        origins: &[origin.as_str()],
        challenge: &challenge,
        user_verification: stage != Stage::SecondFactor,
    };
    let Ok(asserted) = webauthn::assert(
        &client_data,
        &authenticator_data,
        &signature,
        &passkey.public_key,
        passkey.sign_count,
        &expected,
    ) else {
        return Err(rejected(&state, &tenant, &keys, Some(passkey.user), now).await);
    };
    let moved = asserted.sign_count == 0
        || state
            .passkeys
            .advance_count(&tenant, &credential_id, asserted.sign_count)
            .await
            .map_err(Error::Store)?;
    if asserted.clone_suspected || !moved {
        tracing::warn!(
            event = "passkey_clone_suspected",
            tenant = tenant.as_str(),
            "a passkey's counter did not move forward"
        );
        let event = AuditEvent {
            user: Some(passkey.user.clone()),
            reason: Some("passkey_clone_suspected".to_owned()),
            ..AuditEvent::of(AuditKind::Refused)
        };
        record(&state, &tenant, &event, now).await;
        return Err(rejected(&state, &tenant, &keys, Some(passkey.user), now).await);
    }
    let user = passkey.user;
    let reached = step(&state, &tenant, &binding, None, |ceremony| {
        if stage == Stage::SecondFactor {
            ceremony.verified(Method::Passkey {
                user_verified: asserted.user_verified,
            })
        } else {
            ceremony.passkey_sign_in(user)
        }
    })
    .await?;
    if let Some(account) = &signin.account {
        forget(&state, &tenant, account).await;
    }
    settled(&state, &tenant, issuer, &binding, reached).await
}
