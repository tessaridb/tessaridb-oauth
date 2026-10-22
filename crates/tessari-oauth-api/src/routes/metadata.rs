//! `GET /{tenant}/.well-known/oauth-authorization-server` (RFC 8414 §3) and
//! `GET /{tenant}/.well-known/openid-configuration` (OpenID Connect Discovery 1.0 §4): one document under both names.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use tessari_oauth_constants::JWKS_MAX_AGE_SECS;
use tessari_oauth_core::discovery;

use crate::state::PublicState;
use crate::{Error, Result};

pub(super) async fn metadata(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
) -> Result<Response> {
    let (_, issuer) = state.tenant(&tenant)?;
    // The issuer was validated when the configuration was read, so a refusal here is a defect.
    let document =
        discovery::metadata(issuer, state.signing_algorithm).map_err(|_| Error::Internal)?;
    let cache = format!("public, max-age={JWKS_MAX_AGE_SECS}");
    Ok(([(header::CACHE_CONTROL, cache)], Json(document)).into_response())
}
