//! The public router: per tenant, the server metadata and the key set under the read limit, the authorization
//! endpoint under its own, and the token, revocation and pushed-request endpoints under theirs, every form body
//! capped.

mod authorize;
mod jwks;
mod metadata;
mod token;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use tessari_oauth_constants::{AUTHORIZE_BODY_MAX_BYTES, TOKEN_BODY_MAX_BYTES};
use tessari_oauth_core::clients::{ClientDirectory, ClientRegistration};
use tessari_oauth_types::{ClientId, TenantId};

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
    let authorizations = Router::new()
        .route(
            "/{tenant}/oauth2/authorize",
            get(authorize::query).post(authorize::form),
        )
        .layer(DefaultBodyLimit::max(AUTHORIZE_BODY_MAX_BYTES))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::authorizations,
        ));
    let tokens = Router::new()
        .route("/{tenant}/oauth2/token", post(token::token))
        .route("/{tenant}/oauth2/revoke", post(token::revoke))
        .route("/{tenant}/oauth2/par", post(token::par))
        .layer(DefaultBodyLimit::max(TOKEN_BODY_MAX_BYTES))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::tokens,
        ));
    reads
        .merge(authorizations)
        .merge(tokens)
        .fallback(|| async { crate::Error::NotFound })
        .with_state(state)
        .layer(axum::middleware::map_response(|response| async {
            protect(response)
        }))
}

/// The one registration looked up for a request, as the directory the core validates against.
struct Found(Option<ClientRegistration>);

impl ClientDirectory for Found {
    fn find(&self, tenant: &TenantId, client_id: &ClientId) -> Option<ClientRegistration> {
        self.0
            .clone()
            .filter(|found| found.tenant == *tenant && found.client_id == *client_id)
    }
}
