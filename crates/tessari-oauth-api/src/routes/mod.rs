//! The public router: per tenant, the server metadata, the key set and UserInfo under the read limit, the authorization
//! endpoint under its own, the token, revocation and pushed-request endpoints under theirs, and the sign-in steps
//! under theirs, every body capped.

mod authorize;
mod jwks;
mod login;
mod metadata;
mod resume;
mod token;
mod userinfo;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use tessari_oauth_constants::{
    AUTHORIZE_BODY_MAX_BYTES, LOGIN_API_PATH, LOGIN_BODY_MAX_BYTES, TOKEN_BODY_MAX_BYTES,
};
use tessari_oauth_core::clients::{ClientDirectory, ClientRegistration};
use tessari_oauth_types::{ClientId, TenantId};

use crate::headers::{no_store, protect};
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
        .route(
            "/{tenant}/oauth2/userinfo",
            get(userinfo::userinfo).post(userinfo::userinfo),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::reads,
        ));
    let authorizations = Router::new()
        .route(
            "/{tenant}/oauth2/authorize",
            get(authorize::query).post(authorize::form),
        )
        .route("/{tenant}/oauth2/authorize/resume", get(resume::resume))
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
    let logins = Router::new()
        .route(
            &format!("/{{tenant}}{LOGIN_API_PATH}/begin"),
            post(login::begin),
        )
        .route(
            &format!("/{{tenant}}{LOGIN_API_PATH}/identify"),
            post(login::identify),
        )
        .route(
            &format!("/{{tenant}}{LOGIN_API_PATH}/password"),
            post(login::password),
        )
        .route(&format!("/{{tenant}}{LOGIN_API_PATH}/totp"), post(login::totp))
        .route(
            &format!("/{{tenant}}{LOGIN_API_PATH}/recovery"),
            post(login::recovery),
        )
        .route(
            &format!("/{{tenant}}{LOGIN_API_PATH}/passkey/options"),
            post(login::passkey_options),
        )
        .route(
            &format!("/{{tenant}}{LOGIN_API_PATH}/passkey"),
            post(login::passkey),
        )
        .layer(DefaultBodyLimit::max(LOGIN_BODY_MAX_BYTES))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::logins,
        ))
        // A step's answer, refusals and the limit's own included, belongs to one browser's sign-in.
        .layer(axum::middleware::map_response(|response| async {
            no_store(response)
        }));
    reads
        .merge(authorizations)
        .merge(tokens)
        .merge(logins)
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
