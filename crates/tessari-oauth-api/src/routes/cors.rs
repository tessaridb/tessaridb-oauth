//! CORS for browser-facing token calls: only an origin a public client actually redirects to, never a wildcard or
//! credentials. Every check uses the registered client, so an unregistered origin fails closed before the handler.

use axum::extract::{Path, Request, State};
use axum::http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tessari_oauth_core::clients::AuthMethod;

use crate::state::PublicState;
use crate::{Error, Result};

const METHODS: &str = "POST";
const HEADERS: &str = "authorization,dpop,content-type";

fn origin_of(uri: &str) -> Option<&str> {
    let (scheme, rest) = uri.split_once("://")?;
    let host = rest.split('/').next()?;
    let end = scheme.len().checked_add(3)?.checked_add(host.len())?;
    Some(match scheme {
        "http" | "https" => &uri[..end],
        _ => return None,
    })
}

async fn allowed_origin(
    state: &PublicState,
    tenant: &str,
    headers: &HeaderMap,
) -> Result<Option<String>> {
    let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) else {
        return Ok(None);
    };
    let (tenant, _) = state.tenant(tenant)?;
    let clients = state
        .clients
        .page(&tenant, None, 100)
        .await
        .map_err(Error::Store)?;
    if clients.iter().any(|client| {
        client.auth_method == AuthMethod::None
            && client
                .redirect_uris
                .iter()
                .any(|uri| origin_of(uri.as_str()) == Some(origin))
    }) {
        return Ok(Some(origin.to_owned()));
    }
    Err(Error::CrossOrigin)
}

fn decorate(response: &mut Response, origin: &str) {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(origin) {
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, value);
    }
    headers.insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(METHODS),
    );
    headers.insert(
        ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(HEADERS),
    );
}

/// Answer a preflight, with no cookies accepted.
pub(super) async fn preflight(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let origin = allowed_origin(&state, &tenant, &headers).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    if let Some(origin) = origin {
        decorate(&mut response, &origin);
    }
    Ok(response)
}

/// Apply the same registration check to an actual call and its answer.
pub(super) async fn decorated(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    match allowed_origin(&state, &tenant, &headers).await {
        Ok(origin) => {
            let mut response = next.run(request).await;
            if let Some(origin) = origin {
                decorate(&mut response, &origin);
            }
            response
        }
        Err(error) => error.into_response(),
    }
}
