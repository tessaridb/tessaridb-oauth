//! `POST /{tenant}/account/api/passkeys/options` and `POST /{tenant}/account/api/passkeys/register`: the signed-in
//! user registers a new passkey.
//!
//! Both need a session that may change the account's factors (a recent sign-in at the account's level). The options
//! carry a registration challenge issued to this user alone, this issuer's relying-party id, the user's own
//! credentials to exclude, and the key algorithms this issuer checks; the user must be verified. Registering spends
//! the challenge its client data names, once, and only when it was issued to the same user; the response is checked
//! in full against this relying party and origin before the credential is stored, and a credential id already held
//! is refused. A registration signs out the user's other sessions, revokes every refresh family and is recorded.
//! Bodies are JSON and the session cookie is `SameSite=Lax`, so a cross-site page can do neither. No answer may be
//! stored by a cache.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::WEBAUTHN_CHALLENGE_TTL_SECS;
use tessari_oauth_core::webauthn::{Expected, challenge_of, register as checked};
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::passkeys::{Ceremony, Registration};
use tessari_oauth_types::base64url;

use super::account_factors::{Nothing, changed, may_change};
use super::login::{body, relying_party, signed_in};
use super::notice::Change;
use crate::state::PublicState;
use crate::{Error, Result};

/// The COSE algorithms this issuer checks: EdDSA, ES256, RS256.
const ALGORITHMS: [i32; 3] = [-8, -7, -257];

#[derive(Serialize)]
struct User {
    id: String,
    name: String,
}

/// What the browser passes to `navigator.credentials.create`.
#[derive(Serialize)]
struct Options {
    challenge: String,
    rp_id: String,
    user: User,
    exclude: Vec<String>,
    algorithms: [i32; 3],
    user_verification: &'static str,
    timeout_ms: u64,
}

/// What the browser's `navigator.credentials.create` answered, each part base64url.
#[derive(Deserialize)]
pub(super) struct Created {
    client_data_json: String,
    attestation_object: String,
}

/// The passkey a registration stored, and what it ended.
#[derive(Serialize)]
struct Added {
    id: String,
    sessions: usize,
    families: usize,
    access_tokens_end_by: u64,
}

pub(super) async fn options(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Nothing>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let issuer = &*issuer;
    body(read)?;
    let now = (state.clock)();
    let asking = signed_in(&state, &tenant, &headers, now).await?;
    let passkeys = may_change(&state, &tenant, &asking, now).await?.passkeys;
    // A session names an account that existed when it signed in, and accounts are never removed.
    let account = state
        .users
        .find(&tenant, &asking.user)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::Internal)?;
    let challenge = random_secret().map_err(|_| Error::Internal)?;
    state
        .passkeys
        .issue_challenge(
            &tenant,
            &challenge,
            Ceremony::Registration,
            Some(&asking.user),
            now,
        )
        .await
        .map_err(Error::Store)?;
    let options = Options {
        challenge: base64url::encode(&challenge),
        rp_id: relying_party(issuer)?.0,
        user: User {
            id: base64url::encode(asking.user.as_str().as_bytes()),
            name: account.email.as_str().to_owned(),
        },
        exclude: passkeys.into_iter().map(|passkey| passkey.id).collect(),
        algorithms: ALGORITHMS,
        user_verification: "required",
        timeout_ms: WEBAUTHN_CHALLENGE_TTL_SECS
            .checked_mul(1000)
            .ok_or(Error::Internal)?,
    };
    Ok((StatusCode::OK, Json(options)).into_response())
}

pub(super) async fn register(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Created>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let issuer = &*issuer;
    let created = body(read)?;
    let now = (state.clock)();
    let asking = signed_in(&state, &tenant, &headers, now).await?;
    may_change(&state, &tenant, &asking, now).await?;
    let client_data = base64url::decode(&created.client_data_json).map_err(|_| Error::Invalid)?;
    let attestation = base64url::decode(&created.attestation_object).map_err(|_| Error::Invalid)?;
    let challenge = challenge_of(&client_data).ok_or(Error::Invalid)?;
    let challenged = state
        .passkeys
        .spend_challenge(&tenant, &challenge, Ceremony::Registration, now)
        .await
        .map_err(Error::Store)?;
    if challenged.and_then(|challenged| challenged.user).as_ref() != Some(&asking.user) {
        return Err(Error::NothingPending);
    }
    let (rp_id, origin) = relying_party(issuer)?;
    let expected = Expected {
        rp_id: &rp_id,
        origins: &[origin.as_str()],
        challenge: &challenge,
        user_verification: true,
    };
    let registered = checked(&client_data, &attestation, &expected).map_err(|_| Error::Invalid)?;
    let outcome = state
        .passkeys
        .register(&tenant, &asking.user, &registered, now)
        .await
        .map_err(Error::Store)?;
    if outcome == Registration::AlreadyRegistered {
        return Err(Error::AlreadyEnrolled);
    }
    let (sessions, families, access_tokens_end_by) =
        changed(&state, &tenant, &asking, Change::PasskeyAdded, now).await?;
    let added = Added {
        id: base64url::encode(&registered.credential_id),
        sessions,
        families,
        access_tokens_end_by,
    };
    Ok((StatusCode::OK, Json(added)).into_response())
}
