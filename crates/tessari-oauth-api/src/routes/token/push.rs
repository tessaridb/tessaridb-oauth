//! `POST /{tenant}/oauth2/par` (RFC 9126): a client that authenticates as it does at the token endpoint pushes the
//! parameters it would have put in the browser's URL, and they are judged exactly as the authorization endpoint
//! judges them — but every refusal comes back to the client here, since nothing has reached a browser. A request that
//! passes is kept unclaimed and named by a `request_uri` for the minute the browser has to bring it.

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_constants::{PUSHED_REQUEST_TTL_SECS, REQUEST_URI_PREFIX};
use tessari_oauth_core::authorize::{self, Refusal as AuthorizeRefusal};
use tessari_oauth_core::token::Endpoint;
use tessari_oauth_core::{Params, Reason};
use tessari_oauth_types::{ClientId, ErrorCode};

use super::super::Found;
use super::{Failure, authenticate, refusal};
use crate::Error;
use crate::state::PublicState;

/// A pushed request's answer (RFC 9126 §2.2).
#[derive(Serialize)]
struct Pushed {
    request_uri: String,
    expires_in: u64,
}

pub(super) async fn push(
    state: &PublicState,
    endpoint: &Endpoint,
    headers: &HeaderMap,
    params: &Params,
    client_id: Option<&ClientId>,
) -> Result<Response, Failure> {
    let client = authenticate(state, endpoint, headers, params, client_id).await?;
    // The pushed parameters ARE the request; a `request_uri` among them would name another (RFC 9126 §2.1).
    if params.get("request_uri").is_some() {
        return Err(refusal(ErrorCode::InvalidRequest, Reason::RequestUriInPush).into());
    }
    let request = authorize::validate(
        &endpoint.tenant,
        &endpoint.issuer,
        &Found(Some(client)),
        params.iter(),
    )
    .map_err(|refused| {
        let (AuthorizeRefusal::RenderAtServer { error, reason }
        | AuthorizeRefusal::RedirectToClient { error, reason, .. }) = refused;
        refusal(error, reason)
    })?;
    let id = state
        .interactions
        .push(&endpoint.tenant, &request, endpoint.now)
        .await
        .map_err(Error::Store)?;
    Ok((
        StatusCode::CREATED,
        Json(Pushed {
            request_uri: format!("{REQUEST_URI_PREFIX}{id}"),
            expires_in: PUSHED_REQUEST_TTL_SECS,
        }),
    )
        .into_response())
}
