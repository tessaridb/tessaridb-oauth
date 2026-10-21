//! The public router: per tenant, the server metadata and the key set.

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
        .fallback(|| async { crate::Error::NotFound })
        .with_state(state)
        .layer(axum::middleware::map_response(|response| async {
            protect(response)
        }))
}
