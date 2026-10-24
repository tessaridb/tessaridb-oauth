//! `GET /{tenant}/oauth2/jwks`: the keys the rotation rule publishes now, served with the cache lifetime the rule
//! counts on (RFC 7517 §5).

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use tessari_oauth_constants::JWKS_MAX_AGE_SECS;
use tessari_oauth_core::keys::{self, KeyRecord};

use crate::state::PublicState;
use crate::{Error, Result};

pub(super) async fn jwks(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let stored = state.keys.live(&tenant).await.map_err(Error::Store)?;
    let records: Vec<KeyRecord> = stored
        .iter()
        .map(|key| KeyRecord {
            kid: key.kid.clone(),
            created_at: key.created_at,
            compromised: key.compromised,
        })
        .collect();
    let plan = keys::plan(&records, (state.clock)());
    let document = keys::key_set(
        &plan,
        stored.iter().map(|key| (&key.kid, key.public_jwk.as_str())),
    )
    .map_err(|_| Error::Internal)?;
    let cache = format!("public, max-age={JWKS_MAX_AGE_SECS}");
    Ok((
        [
            (header::CACHE_CONTROL, cache),
            (header::CONTENT_TYPE, "application/jwk-set+json".to_owned()),
        ],
        document,
    )
        .into_response())
}
