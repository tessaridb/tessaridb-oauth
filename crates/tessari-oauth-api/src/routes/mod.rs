//! The public router: per tenant, the server metadata, the key set, UserInfo and the sign-in and consent pages under
//! the read limit, the authorization endpoint under its own, the token, revocation and pushed-request endpoints under
//! theirs, the sign-in steps under theirs, and the account portal's requests under theirs, every body capped.

mod account;
mod account_factors;
mod account_me;
mod account_passkeys;
mod account_password;
mod account_sessions;
mod account_totp;
mod authorize;
mod browser;
mod jwks;
mod login;
mod metadata;
mod pages;
mod resume;
mod token;
mod userinfo;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use tessari_oauth_constants::{
    ACCOUNT_API_PATH, AUTHORIZE_BODY_MAX_BYTES, LOGIN_API_PATH, LOGIN_BODY_MAX_BYTES,
    TOKEN_BODY_MAX_BYTES,
};
use tessari_oauth_core::clients::{ClientDirectory, ClientRegistration};
use tessari_oauth_types::{ClientId, TenantId};

use crate::headers::{no_store, protect};
use crate::state::PublicState;

/// The routes of the public listener over `state`. Unknown paths answer 404 with the same headers as every route.
pub fn public_router(state: PublicState) -> Router {
    // Limits sit on the matched routes only: a path that matches nothing costs no store work, so it is not counted.
    let pages = pages::ASSETS
        .iter()
        .fold(Router::new(), |router, (path, _, _)| {
            router.route(&format!("/{{tenant}}{path}"), get(pages::asset))
        });
    let reads = pages
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
        .route(
            &format!("/{{tenant}}{LOGIN_API_PATH}/consent"),
            get(login::consent).post(login::decide),
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
    let accounts = Router::new()
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/grants"),
            get(account::grants),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/grants/revoke"),
            post(account::revoke),
        )
        .route(&format!("/{{tenant}}{ACCOUNT_API_PATH}/me"), get(account_me::me))
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/passkeys/options"),
            post(account_passkeys::options),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/passkeys/register"),
            post(account_passkeys::register),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/passkeys/remove"),
            post(account_factors::remove_passkey),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/recovery-codes"),
            post(account_factors::issue_recovery_codes),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/totp/begin"),
            post(account_totp::begin),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/totp/confirm"),
            post(account_totp::confirm),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/password"),
            post(account_password::change),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/sessions"),
            get(account_sessions::sessions),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/sessions/end"),
            post(account_sessions::end),
        )
        .route(
            &format!("/{{tenant}}{ACCOUNT_API_PATH}/sessions/end-all"),
            post(account_sessions::end_all),
        )
        .layer(DefaultBodyLimit::max(LOGIN_BODY_MAX_BYTES))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::accounts,
        ))
        // What a user's own account holds belongs to that user's browser alone.
        .layer(axum::middleware::map_response(|response| async {
            no_store(response)
        }));
    reads
        .merge(authorizations)
        .merge(tokens)
        .merge(logins)
        .merge(accounts)
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
