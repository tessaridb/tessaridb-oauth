//! The token endpoint's answers: tokens (RFC 6749 §5.1) or a refusal (§5.2), neither ever stored by a cache.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_constants::ACCESS_TOKEN_TTL_SECS;
use tessari_oauth_core::token::Refusal;
use tessari_oauth_types::{ErrorCode, KeyThumbprint, RefreshToken, ScopeSet};

/// A successful token response (RFC 6749 §5.1).
#[derive(Serialize)]
pub(super) struct Issued {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    scope: String,
}

impl Issued {
    /// The answer for `access_token` over `scopes`, with `refresh_token` when one was issued: of type `DPoP` when the
    /// access token is bound to a key (RFC 9449 §5), `Bearer` otherwise.
    pub(super) fn new(
        access_token: String,
        refresh_token: Option<&RefreshToken>,
        scopes: &ScopeSet,
        bound_to: Option<&KeyThumbprint>,
    ) -> Self {
        Self {
            access_token,
            token_type: if bound_to.is_some() { "DPoP" } else { "Bearer" },
            expires_in: ACCESS_TOKEN_TTL_SECS,
            refresh_token: refresh_token.map(|token| token.expose().to_owned()),
            scope: scopes.iter().collect::<Vec<_>>().join(" "),
        }
    }
}

/// An error response (RFC 6749 §5.2): the code and nothing the request supplied.
#[derive(Serialize)]
struct Refused {
    error: &'static str,
}

/// `refused` as an error response: 401 for a client that did not authenticate, 400 otherwise.
pub(super) fn answer_refusal(refused: Refusal, basic: bool) -> Response {
    let unauthenticated = refused.error == ErrorCode::InvalidClient;
    let status = if unauthenticated {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::BAD_REQUEST
    };
    let mut response = (
        status,
        Json(Refused {
            error: refused.error.as_str(),
        }),
    )
        .into_response();
    if unauthenticated && basic {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"token\""),
        );
    }
    no_store(response)
}

/// Mark `response` as never to be stored by any cache (RFC 6749 §5.1).
pub(super) fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}
