//! The admin console's own listener: operators sign in at their company's issuer as its client `admin-console`,
//! and the console keeps their session on its own origin.

mod signin;

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use tessari_oauth_storage::admin::AdminService;
use tessari_oauth_storage::companies::Served;
use tessari_oauth_types::Clock;

/// The state the admin router serves from; shared read-only, so no lock is ever taken.
#[derive(Clone)]
pub struct AdminState {
    /// Console sign-ins and sessions.
    pub admin: Arc<AdminService>,
    /// The companies this node serves and their issuers.
    pub served: Arc<Served>,
    /// The console's base URL, as `TESSARIDB_OAUTH_ADMIN_URL` gives it.
    pub console: Arc<str>,
    /// The clock sign-ins and sessions are judged at.
    pub clock: Clock,
}

impl AdminState {
    /// Whether the console is reached over https, which decides how its cookies are set.
    fn secure(&self) -> bool {
        self.console.starts_with("https://")
    }
}

/// The routes of the admin listener over `state`. Unknown paths answer 404.
pub fn admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/{company}/signin", get(signin::signin))
        .fallback(|| async { crate::Error::NotFound })
        .with_state(state)
        .layer(axum::middleware::map_response(|response| async {
            crate::headers::no_store(crate::headers::protect(response))
        }))
}
