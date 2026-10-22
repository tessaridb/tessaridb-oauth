//! The admin console's own listener: operators sign in at their company's issuer as its client `admin-console`,
//! and the console keeps their session on its own origin.

mod callback;
mod change;
mod operator;
mod policy;
mod session;
mod signin;
mod users;
mod users_read;

use std::sync::Arc;

use axum::Router;
use axum::http::HeaderValue;
use axum::routing::{get, post};
use tessari_oauth_storage::admin::AdminService;
use tessari_oauth_storage::audit::AuditEvent;
use tessari_oauth_storage::audit::AuditService;
use tessari_oauth_storage::clients::ClientService;
use tessari_oauth_storage::codes::CodeService;
use tessari_oauth_storage::companies::Served;
use tessari_oauth_storage::operators::OperatorService;
use tessari_oauth_storage::policies::PolicyService;
use tessari_oauth_storage::refresh::RefreshService;
use tessari_oauth_storage::sessions::SessionService;
use tessari_oauth_storage::throttle::{Limit, ThrottleService};
use tessari_oauth_storage::users::UserService;
use tessari_oauth_types::{Clock, TenantId};

use crate::{Error, Result};

/// The sign-in cookie's name when the console is reached in the clear; over https it carries the `__Host-` prefix.
const SIGNIN_COOKIE: &str = "tessari-admin-signin";
/// The session cookie's name when the console is reached in the clear; over https it carries the `__Host-` prefix.
const SESSION_COOKIE: &str = "tessari-admin";

/// The state the admin router serves from; shared read-only, so no lock is ever taken.
#[derive(Clone)]
pub struct AdminState {
    /// Console sign-ins and sessions.
    pub admin: Arc<AdminService>,
    /// Authorization codes, spent once by the callback.
    pub codes: Arc<CodeService>,
    /// Client registrations: the console's own, whose bindings a code is checked against.
    pub clients: Arc<ClientService>,
    /// Operator grants: a sign-in without one opens nothing.
    pub operators: Arc<OperatorService>,
    /// The audit trail.
    pub audit: Arc<AuditService>,
    /// Issuer sessions: a console session ends with the one it came from.
    pub sessions: Arc<SessionService>,
    /// Company policies the console reads and changes.
    pub policies: Arc<PolicyService>,
    /// The company's user accounts the console lists and moves between active and disabled.
    pub users: Arc<UserService>,
    /// Refresh families, revoked when their user is disabled.
    pub refresh: Arc<RefreshService>,
    /// The request counters every admin route is counted in.
    pub throttle: Arc<ThrottleService>,
    /// How many requests a client address may make to the console per window.
    pub limit: Limit,
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

    /// Append `event` to `tenant`'s trail; a trail that does not take it is logged, never answered.
    async fn record(&self, tenant: &TenantId, event: &AuditEvent) {
        if let Err(failure) = self.audit.record(tenant, event, (self.clock)()).await {
            tracing::error!(
                event = "audit_unrecorded",
                tenant = tenant.as_str(),
                category = ?failure.category(),
                "an admin console event could not be appended to the audit trail"
            );
        }
    }

    /// `name` as this console sets it: `__Host-` prefixed over https.
    fn cookie_name(&self, name: &str) -> String {
        if self.secure() {
            format!("__Host-{name}")
        } else {
            name.to_owned()
        }
    }

    /// The cookie `name` holding `value` for `max_age` seconds: `Secure` over https, always `HttpOnly` on `Path=/`.
    fn cookie(
        &self,
        name: &str,
        value: &str,
        same_site: &str,
        max_age: u64,
    ) -> Result<HeaderValue> {
        let secure = if self.secure() { " Secure;" } else { "" };
        HeaderValue::from_str(&format!(
            "{}={value}; Path=/;{secure} HttpOnly; SameSite={same_site}; Max-Age={max_age}",
            self.cookie_name(name)
        ))
        .map_err(|_| Error::Internal)
    }
}

/// The routes of the admin listener over `state`. Unknown paths answer 404.
pub fn admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/{company}/signin", get(signin::signin))
        .route("/admin/{company}/callback", get(callback::callback))
        .route("/admin/{company}/api/me", get(session::me))
        .route("/admin/{company}/signout", post(session::signout))
        .route(
            "/admin/{company}/api/policy/two-factor",
            get(policy::two_factor).put(policy::set_two_factor),
        )
        .route("/admin/{company}/api/users", get(users_read::list))
        .route("/admin/{company}/api/users/{user}", get(users_read::one))
        .route(
            "/admin/{company}/api/users/{user}/disable",
            post(users::disable),
        )
        .route(
            "/admin/{company}/api/users/{user}/enable",
            post(users::enable),
        )
        .fallback(|| async { crate::Error::NotFound })
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::throttle::admins,
        ))
        .with_state(state)
        .layer(axum::middleware::map_response(|response| async {
            crate::headers::no_store(crate::headers::protect(response))
        }))
}
