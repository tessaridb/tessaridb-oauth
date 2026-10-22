//! `GET|POST /{tenant}/oauth2/authorize` (RFC 6749 §4.1.1; the form per OpenID Connect Core §3.1.2.1): the browser's
//! way into the code flow.
//!
//! The request is judged in the core's fixed order. A refusal before the redirect URI is proven the client's own is
//! shown on a page here and sent nowhere, so a URI an attacker wrote into the request never receives an answer from
//! this domain; a later refusal goes back to that URI with `state` and the issuer (RFC 9207). A `request_uri` brings a
//! request its client pushed (RFC 9126): claimed once by that client, it is the request, and nothing else in the
//! query is read; one that cannot be claimed is refused at the server. A request that asks for
//! no page is refused with `login_required`, because no session can answer it yet. A valid request is kept as a
//! pending authorization bound to the browser that brought it, by a browser cookie the browser keeps or this server
//! draws, and the browser is sent to sign in carrying that record's id and nothing else. Every refusal
//! is appended to the tenant's audit trail — identifiers and the reason, never the request's values — and is answered
//! whether or not its record lands. No answer may be stored by a cache.

use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tessari_oauth_constants::LOGIN_PATH;
use tessari_oauth_core::Reason;
use tessari_oauth_core::authorize::{self, Refusal};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{ClientId, ErrorCode, TenantId, Timestamp};

use super::Found;
use super::browser::{browser_cookie, held_or_drawn};
use crate::Error;
use crate::headers::no_store;
use crate::state::PublicState;

type Pairs = Vec<(String, String)>;

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

/// Judge the request's `pairs` — `None` when they could not be read — and answer it.
async fn respond(
    state: &PublicState,
    tenant: &str,
    headers: &HeaderMap,
    pairs: Option<Pairs>,
) -> crate::Result<Response> {
    let (tenant, issuer) = state.tenant(tenant)?;
    let now = (state.clock)();
    let browser = held_or_drawn(headers)?;
    let Some(pairs) = pairs else {
        let refused = Refusal::RenderAtServer {
            error: ErrorCode::InvalidRequest,
            reason: Reason::BodyNotForm,
        };
        return answer(state, &tenant, None, refused, now).await;
    };
    let client_id = pairs
        .iter()
        .find(|(name, _)| name == "client_id")
        .and_then(|(_, raw)| ClientId::parse(raw).ok());
    let named = pairs
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()));
    let (request, kept) = match authorize::pushed(named) {
        // A pushed request was judged in full when it was pushed; claimed, it is the request (RFC 9126 §4).
        Ok(Some((client, id))) => {
            let claimed = state
                .interactions
                .claim(&tenant, &id, &client, &browser, now)
                .await
                .map_err(Error::Store)?;
            let Some(request) = claimed else {
                let refused = Refusal::RenderAtServer {
                    error: ErrorCode::InvalidRequest,
                    reason: Reason::RequestUriUnknown,
                };
                return answer(state, &tenant, Some(&client), refused, now).await;
            };
            (request, Some(id))
        }
        Ok(None) => {
            let found = match &client_id {
                Some(client_id) => state
                    .clients
                    .find(&tenant, client_id)
                    .await
                    .map_err(Error::Store)?,
                None => None,
            };
            match authorize::validate(&tenant, issuer, &Found(found), pairs) {
                Ok(request) => (request, None),
                Err(refused) => {
                    return answer(state, &tenant, client_id.as_ref(), refused, now).await;
                }
            }
        }
        Err(refused) => return answer(state, &tenant, client_id.as_ref(), refused, now).await,
    };
    if request.silent {
        // No session exists to answer from, and a silent request may never be shown a page.
        let refused = Refusal::RedirectToClient {
            redirect_uri: request.redirect_uri,
            error: ErrorCode::LoginRequired,
            state: request.state,
            iss: issuer.to_owned(),
            reason: Reason::SilentWithoutSession,
        };
        return answer(state, &tenant, Some(&request.client_id), refused, now).await;
    }
    let id = match kept {
        Some(id) => id,
        None => state
            .interactions
            .open(&tenant, &request, &browser, now)
            .await
            .map_err(Error::Store)?,
    };
    let mut response = see_other(&format!("{issuer}{LOGIN_PATH}?interaction={id}"))?;
    response
        .headers_mut()
        .insert(header::SET_COOKIE, browser_cookie(&browser)?);
    Ok(response)
}

/// Record `refused` for the client the request named, then answer it where it may go.
async fn answer(
    state: &PublicState,
    tenant: &TenantId,
    client_id: Option<&ClientId>,
    refused: Refusal,
    now: Timestamp,
) -> crate::Result<Response> {
    let (Refusal::RenderAtServer { error, reason }
    | Refusal::RedirectToClient { error, reason, .. }) = &refused;
    tracing::warn!(
        event = "authorization_refused",
        tenant = tenant.as_str(),
        client = client_id.map(ClientId::as_str),
        reason = ?reason,
        error = error.as_str(),
        "an authorization request was refused"
    );
    let event = AuditEvent {
        client_id: client_id.cloned(),
        reason: Some(format!("{reason:?}")),
        ..AuditEvent::of(AuditKind::Refused)
    };
    if let Err(failure) = state.audit.record(tenant, &event, now).await {
        tracing::error!(
            event = "audit_unrecorded",
            tenant = tenant.as_str(),
            category = ?failure.category(),
            "a refusal could not be appended to the audit trail"
        );
    }
    match refused {
        Refusal::RenderAtServer { error, .. } => Ok(page(error)),
        Refusal::RedirectToClient {
            redirect_uri,
            error,
            state,
            iss,
            ..
        } => {
            let mut target = url::Url::parse(&redirect_uri).map_err(|_| Error::Internal)?;
            {
                let mut query = target.query_pairs_mut();
                query.append_pair("error", error.as_str());
                if let Some(state) = &state {
                    query.append_pair("state", state);
                }
                query.append_pair("iss", &iss);
            }
            see_other(target.as_str())
        }
    }
}

/// The page shown for a refusal that may not be sent to the client: the `error` code and nothing the request carried.
pub(super) fn page(error: ErrorCode) -> Response {
    let body = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>Sign-in request refused</title></head>\n\
         <body><h1>This sign-in request cannot be completed</h1>\n<p>The application sent a request this server does \
         not accept ({}). Return to the application and start again.</p></body>\n</html>\n",
        error.as_str()
    );
    no_store(
        (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            body,
        )
            .into_response(),
    )
}

/// Send the browser to `location` (RFC 9110 §15.4.4: the next request is a GET whatever this one was).
pub(super) fn see_other(location: &str) -> crate::Result<Response> {
    let location = HeaderValue::from_str(location).map_err(|_| Error::Internal)?;
    Ok(no_store(
        (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response(),
    ))
}
