//! The public router: per tenant, the server metadata and the key set under the read limit, and the token and
//! revocation endpoints under their own limit with their bodies capped.

mod jwks;
mod metadata;
mod token;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use tessari_oauth_constants::TOKEN_BODY_MAX_BYTES;

use crate::headers::protect;
use crate::state::PublicState;

/// The routes of the public listener over `state`. Unknown paths answer 404 with the same headers as every route.
pub fn public_router(state: PublicState) -> Router {
    // Limits sit on the matched routes only: a path that matches nothing costs no store work, so it is not counted.
    let reads = Router::new()
        .route(
            "/{tenant}/.well-known/oauth-authorization-server",
            get(metadata::metadata),
        )
        .route("/{tenant}/oauth2/jwks", get(jwks::jwks))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::reads,
        ));
    let tokens = Router::new()
        .route("/{tenant}/oauth2/token", post(token::token))
        .route("/{tenant}/oauth2/revoke", post(token::revoke))
        .layer(DefaultBodyLimit::max(TOKEN_BODY_MAX_BYTES))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::tokens,
        ));
    reads
        .merge(tokens)
        .fallback(|| async { crate::Error::NotFound })
        .with_state(state)
        .layer(axum::middleware::map_response(|response| async {
            protect(response)
        }))
}
