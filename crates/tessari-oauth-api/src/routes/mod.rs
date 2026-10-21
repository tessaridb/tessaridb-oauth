//! The public router: per tenant, the server metadata and the key set, both under the read limit.

mod jwks;
mod metadata;

use axum::Router;
use axum::routing::get;

use crate::headers::protect;
use crate::state::PublicState;

/// The routes of the public listener over `state`. Unknown paths answer 404 with the same headers as every route.
pub fn public_router(state: PublicState) -> Router {
    Router::new()
        .route(
            "/{tenant}/.well-known/oauth-authorization-server",
            get(metadata::metadata),
        )
        .route("/{tenant}/oauth2/jwks", get(jwks::jwks))
        // On the matched routes only: a path that matches nothing costs no store work, so it is not counted.
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::reads,
        ))
        .fallback(|| async { crate::Error::NotFound })
        .with_state(state)
        .layer(axum::middleware::map_response(|response| async {
            protect(response)
        }))
}
