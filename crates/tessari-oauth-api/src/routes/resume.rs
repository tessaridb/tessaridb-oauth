//! `GET /{tenant}/oauth2/authorize/resume?interaction=<id>`: the pending authorization a finished sign-in continues.
//!
//! The request must still be pending and have been brought by this browser, as its browser cookie says, or it is
//! refused on a page here and sent nowhere: the redirect URI it carried is no longer known to be the one to answer. A
//! browser with no session at this issuer is sent to sign in for it.
//! When the user's consent to this client covers every scope and resource asked for, under the consent policy in
//! force, the request is taken, once, and answered at its redirect URI with a code bound to the client, the redirect
//! URI, the PKCE challenge, the user and the tenant, its `state`, and the issuer (RFC 9207); otherwise the browser is
//! sent to be asked, and the request waits. A request that asked for no page (`prompt=none`) is never shown one: where
//! it would be, it is answered at its redirect URI with `login_required` or `consent_required`, and the refusal is
//! recorded. Where the company's two-factor policy requires a second factor the account does not hold, no code is
//! issued: the browser is sent to the account page to enrol one, or a request that asked for no page is answered
//! with `interaction_required`.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use tessari_oauth_constants::{
    ACCOUNT_PATH, AUTHORIZATION_CODE_TTL_SECS, CONSENT_PATH, CONSENT_POLICY_VERSION, LOGIN_PATH,
    SESSION_COOKIE,
};
use tessari_oauth_core::Reason;
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_core::codes::{CodeAuthentication, IssuedCode};
use tessari_oauth_core::consents::{ConsentRequest, Coverage};
use tessari_oauth_core::two_factor::enrolment_due;
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_storage::sessions::Session;
use tessari_oauth_types::{
    AuthorizationCode, BrowserBinding, ErrorCode, SessionSecret, TenantId, Timestamp, UserId,
    base64url,
};

use super::authorize::{page, record_refused, see_other};
use super::browser::held;
use super::login::{cookie, well_formed};
use crate::state::PublicState;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(super) struct Resume {
    interaction: Option<String>,
}

pub(super) async fn resume(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    query: std::result::Result<Query<Resume>, QueryRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let issuer = &*issuer;
    let now = (state.clock)();
    let (Some(id), Some(browser)) = (
        query
            .ok()
            .and_then(|Query(resume)| resume.interaction)
            .filter(|id| well_formed(id)),
        held(&headers),
    ) else {
        return Ok(page(ErrorCode::InvalidRequest));
    };
    let Some(request) = state
        .interactions
        .find(&tenant, &id, &browser, now)
        .await
        .map_err(Error::Store)?
    else {
        return Ok(page(ErrorCode::InvalidRequest));
    };
    let session = match cookie(&headers, SESSION_COOKIE) {
        Some(value) => state
            .sessions
            .find(&tenant, &SessionSecret::from_secret(value), now)
            .await
            .map_err(Error::Store)?,
        None => None,
    };
    let sign_in = format!("{issuer}{LOGIN_PATH}?interaction={id}");
    let Some(session) = session else {
        return if request.silent {
            silently_refused(
                &state,
                &tenant,
                issuer,
                (&id, &browser),
                (ErrorCode::LoginRequired, Reason::SilentWithoutSession),
                now,
            )
            .await
        } else {
            see_other(&sign_in)
        };
    };
    let signed_in_for = now
        .unix_secs()
        .saturating_sub(session.auth_time.unix_secs());
    if request
        .max_age
        .is_some_and(|max_age| signed_in_for > max_age)
    {
        return if request.silent {
            silently_refused(
                &state,
                &tenant,
                issuer,
                (&id, &browser),
                (ErrorCode::LoginRequired, Reason::SilentSignInTooOld),
                now,
            )
            .await
        } else {
            see_other(&sign_in)
        };
    }
    if must_enrol(&state, &tenant, &session.user).await? {
        return if request.silent {
            silently_refused(
                &state,
                &tenant,
                issuer,
                (&id, &browser),
                (ErrorCode::InteractionRequired, Reason::SilentEnrolmentDue),
                now,
            )
            .await
        } else {
            see_other(&format!("{issuer}{ACCOUNT_PATH}"))
        };
    }
    let asked = ConsentRequest {
        scopes: request.scopes.clone(),
        resources: request.resources.clone(),
    };
    let coverage = state
        .consents
        .check(
            &tenant,
            &session.user,
            &request.client_id,
            &asked,
            CONSENT_POLICY_VERSION,
        )
        .await
        .map_err(Error::Store)?;
    match coverage {
        Coverage::Covered => {
            match issued(&state, &tenant, issuer, (&id, &browser), session, now).await? {
                Some(target) => see_other(&target),
                None => Ok(page(ErrorCode::InvalidRequest)),
            }
        }
        Coverage::Prompt { .. } if request.silent => {
            silently_refused(
                &state,
                &tenant,
                issuer,
                (&id, &browser),
                (ErrorCode::ConsentRequired, Reason::SilentWithoutConsent),
                now,
            )
            .await
        }
        Coverage::Prompt { .. } => see_other(&format!("{issuer}{CONSENT_PATH}?interaction={id}")),
    }
}

/// Whether `user` in `tenant` must enrol a second factor, under the company's policy, before a code is issued.
pub(super) async fn must_enrol(
    state: &PublicState,
    tenant: &TenantId,
    user: &UserId,
) -> Result<bool> {
    let policy = state
        .policies
        .two_factor(tenant)
        .await
        .map_err(Error::Store)?;
    // Only a policy that would make an account holding nothing enrol is worth reading the factors for.
    if !enrolment_due(policy, false) {
        return Ok(false);
    }
    let app = state
        .factors
        .summary(tenant, user)
        .await
        .map_err(Error::Store)?
        .totp;
    let passkeys = state
        .passkeys
        .list(tenant, user)
        .await
        .map_err(Error::Store)?;
    Ok(enrolment_due(policy, app || !passkeys.is_empty()))
}

/// Take the pending authorization `id` that `browser` brought in `tenant` at `now`, once, record its refusal for
/// `reason`, and send the browser to its redirect URI with `error`: a request that asked for no page is answered
/// rather than shown one.
async fn silently_refused(
    state: &PublicState,
    tenant: &TenantId,
    issuer: &str,
    (id, browser): (&str, &BrowserBinding),
    (error, reason): (ErrorCode, Reason),
    now: Timestamp,
) -> Result<Response> {
    let taken = state
        .interactions
        .finish(tenant, id, browser, now)
        .await
        .map_err(Error::Store)?;
    match taken {
        Some(request) => {
            record_refused(
                state,
                tenant,
                Some(&request.client_id),
                (error, reason),
                now,
            )
            .await;
            see_other(&refused_at(&request, issuer, error)?)
        }
        None => Ok(page(ErrorCode::InvalidRequest)),
    }
}

/// The address of `request`'s redirect URI refusing it with `error`, its `state` and the issuer (RFC 6749 §4.1.2.1,
/// RFC 9207).
pub(super) fn refused_at(
    request: &AuthorizationRequest,
    issuer: &str,
    error: ErrorCode,
) -> Result<String> {
    let mut target = url::Url::parse(&request.redirect_uri).map_err(|_| Error::Internal)?;
    {
        let mut query = target.query_pairs_mut();
        query.append_pair("error", error.as_str());
        if let Some(state) = &request.state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", issuer);
    }
    Ok(target.into())
}

/// Take the pending authorization `id` that `browser` brought in `tenant` for the user of `session` at `now`, once,
/// and answer the address of its redirect URI carrying a fresh code that records how that user signed in; `None` when
/// another request took it first.
pub(super) async fn issued(
    state: &PublicState,
    tenant: &TenantId,
    issuer: &str,
    (id, browser): (&str, &BrowserBinding),
    session: Session,
    now: Timestamp,
) -> Result<Option<String>> {
    let Some(request) = state
        .interactions
        .finish(tenant, id, browser, now)
        .await
        .map_err(Error::Store)?
    else {
        return Ok(None);
    };
    let drawn = random_secret().map_err(|_| Error::Internal)?;
    let value = base64url::encode(&drawn);
    let expires_at = now
        .unix_secs()
        .checked_add(AUTHORIZATION_CODE_TTL_SECS)
        .ok_or(Error::Internal)?;
    let issued = IssuedCode {
        tenant: tenant.clone(),
        client_id: request.client_id,
        user: session.user,
        redirect_uri: request.redirect_uri.clone(),
        challenge: request.challenge,
        scopes: request.scopes,
        resources: request.resources,
        expires_at: Timestamp::from_unix_secs(expires_at),
        authentication: CodeAuthentication {
            auth_time: session.auth_time,
            methods: session.methods,
            sid: session.sid,
        },
        nonce: request.nonce,
        dpop_jkt: request.dpop_jkt,
    };
    state
        .codes
        .issue(&AuthorizationCode::from_secret(value.clone()), &issued)
        .await
        .map_err(Error::Store)?;
    let mut target = url::Url::parse(&request.redirect_uri).map_err(|_| Error::Internal)?;
    {
        let mut query = target.query_pairs_mut();
        query.append_pair("code", &value);
        if let Some(state) = &request.state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", issuer);
    }
    Ok(Some(target.into()))
}
