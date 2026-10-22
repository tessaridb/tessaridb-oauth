//! `GET|POST /{tenant}/oauth2/logout` (OpenID Connect RP-Initiated Logout 1.0 §2-§3): a client asks the issuer to end
//! the session the browser holds here.
//!
//! The request must carry an `id_token_hint` this tenant signed; it names the client and the session, and nothing is
//! ended without it, so a page elsewhere cannot sign whoever visits it out. A `client_id`, when given, must be the
//! hint's own. The session the browser's cookie holds is ended only when it is the session the hint names, and the
//! ending is recorded. The browser is sent back only to a `post_logout_redirect_uri` the client registered, exactly,
//! with `state`; any other value is never followed and the issuer shows its own page instead. A refusal is a page
//! here, sent nowhere and carrying nothing the request did. No answer may be stored by a cache.

use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tessari_oauth_constants::SESSION_COOKIE;
use tessari_oauth_core::Params;
use tessari_oauth_core::logout::{self, Hint};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{ClientId, SessionSecret, TenantId, Timestamp, UserId};

use super::authorize::see_other;
use super::login::{cleared_session_cookie, cookie, record};
use super::userinfo::published_keys;
use crate::Error;
use crate::headers::no_store;
use crate::state::PublicState;

type Pairs = Vec<(String, String)>;

/// The reason a logout's session ending is recorded under.
const RP_INITIATED: &str = "rp_initiated";

pub(super) async fn query(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    pairs: Result<Query<Pairs>, QueryRejection>,
) -> crate::Result<Response> {
    respond(
        &state,
        &tenant,
        &headers,
        pairs.map(|Query(pairs)| pairs).ok(),
    )
    .await
}

pub(super) async fn form(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    pairs: Result<Form<Pairs>, FormRejection>,
) -> crate::Result<Response> {
    respond(
        &state,
        &tenant,
        &headers,
        pairs.map(|Form(pairs)| pairs).ok(),
    )
    .await
}

/// Judge the request's `pairs` (`None` when they could not be read) and answer it.
async fn respond(
    state: &PublicState,
    tenant: &str,
    headers: &HeaderMap,
    pairs: Option<Pairs>,
) -> crate::Result<Response> {
    let (tenant, issuer) = state.tenant(tenant)?;
    let now = (state.clock)();
    let Some(params) = pairs.and_then(|pairs| Params::from_pairs(pairs).ok()) else {
        return Ok(refused(state, &tenant, "logout_unreadable", now).await);
    };
    let Some(token) = params.get("id_token_hint") else {
        return Ok(refused(state, &tenant, "logout_without_hint", now).await);
    };
    let keys = published_keys(state, &tenant, now).await?;
    let Ok(hint) = logout::read_hint(token, issuer, state.signing_algorithm, &keys) else {
        return Ok(refused(state, &tenant, "logout_hint_refused", now).await);
    };
    if params
        .get("client_id")
        .is_some_and(|client| client != hint.client_id)
    {
        return Ok(refused(state, &tenant, "logout_other_client", now).await);
    }
    let Ok(client_id) = ClientId::parse(hint.client_id.as_str()) else {
        return Ok(refused(state, &tenant, "logout_unknown_client", now).await);
    };
    let Some(client) = state
        .clients
        .find(&tenant, &client_id)
        .await
        .map_err(Error::Store)?
    else {
        return Ok(refused(state, &tenant, "logout_unknown_client", now).await);
    };
    let ended = end_hinted(state, &tenant, headers, &hint, now).await?;
    let registered = params.get("post_logout_redirect_uri").filter(|asked| {
        client
            .post_logout_redirect_uris
            .iter()
            .any(|uri| uri.as_str() == *asked)
    });
    let mut answer = match registered {
        Some(uri) => {
            let mut target = url::Url::parse(uri).map_err(|_| Error::Internal)?;
            if let Some(state) = params.get("state") {
                target.query_pairs_mut().append_pair("state", state);
            }
            see_other(target.as_str())?
        }
        None => signed_out(),
    };
    if ended {
        answer
            .headers_mut()
            .append(header::SET_COOKIE, cleared_session_cookie()?);
    }
    Ok(answer)
}

/// End the session the request's cookie holds in `tenant` when it is the one `hint` names, recording it; whether
/// one was ended.
async fn end_hinted(
    state: &PublicState,
    tenant: &TenantId,
    headers: &HeaderMap,
    hint: &Hint,
    now: Timestamp,
) -> crate::Result<bool> {
    let Some(value) = cookie(headers, SESSION_COOKIE) else {
        return Ok(false);
    };
    let secret = SessionSecret::from_secret(value);
    let Some(session) = state
        .sessions
        .find(tenant, &secret, now)
        .await
        .map_err(Error::Store)?
    else {
        return Ok(false);
    };
    if session.sid != hint.session_id
        || !state
            .sessions
            .end(tenant, &secret)
            .await
            .map_err(Error::Store)?
    {
        return Ok(false);
    }
    recorded(state, tenant, &session.user, now).await;
    Ok(true)
}

/// Record that `user`'s session in `tenant` was ended at a client's request.
async fn recorded(state: &PublicState, tenant: &TenantId, user: &UserId, now: Timestamp) {
    let event = AuditEvent {
        user: Some(user.clone()),
        reason: Some(RP_INITIATED.to_owned()),
        ..AuditEvent::of(AuditKind::SessionsEnded)
    };
    record(state, tenant, &event, now).await;
}

/// Record a refused logout for `reason`, then show the refusal page.
async fn refused(state: &PublicState, tenant: &TenantId, reason: &str, now: Timestamp) -> Response {
    tracing::warn!(
        event = "logout_refused",
        tenant = tenant.as_str(),
        reason,
        "a logout request was refused"
    );
    let event = AuditEvent {
        reason: Some(reason.to_owned()),
        ..AuditEvent::of(AuditKind::Refused)
    };
    record(state, tenant, &event, now).await;
    page(
        StatusCode::BAD_REQUEST,
        "Sign-out request refused",
        "This sign-out request cannot be completed",
        "The application sent a request this server does not accept, so nothing was changed. Return to the \
         application and sign out from there again.",
    )
}

/// The page shown when the browser is not sent back to the client.
fn signed_out() -> Response {
    page(
        StatusCode::OK,
        "Signed out",
        "Sign-out finished",
        "The application asked this server to end your session. You can close this page.",
    )
}

/// A page of `status` with `title`, `heading` and `text`, none of which carries a request value.
fn page(status: StatusCode, title: &str, heading: &str, text: &str) -> Response {
    let body = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>{title}</title></head>\n\
         <body><h1>{heading}</h1>\n<p>{text}</p></body>\n</html>\n"
    );
    no_store(
        (
            status,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            body,
        )
            .into_response(),
    )
}
