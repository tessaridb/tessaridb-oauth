//! The admin console's own listener: operators sign in at their company's issuer as its client `admin-console`,
//! and the console keeps their session on its own origin.

mod audit;
mod callback;
mod change;
mod clients;
mod clients_read;
mod companies;
mod console;
mod enrolment;
mod operator;
mod operators;
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
use tessari_oauth_storage::companies::{CompanyService, Served};
use tessari_oauth_storage::enrolments::EnrolmentService;
use tessari_oauth_storage::operators::OperatorService;
use tessari_oauth_storage::policies::PolicyService;
use tessari_oauth_storage::refresh::RefreshService;
use tessari_oauth_storage::sessions::SessionService;
use tessari_oauth_storage::tenants::TenantService;
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
    /// Enrolment codes, issued to accounts that have never set a password.
    pub enrolments: Arc<EnrolmentService>,
    /// The company directory the `system` console creates companies in.
    pub companies: Arc<CompanyService>,
    /// Company databases, made when a company is created.
    pub tenants: Arc<TenantService>,
    /// The public base URL every company's issuer is under, as `TESSARIDB_OAUTH_PUBLIC_URL` gives it.
    pub public: Arc<str>,
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
        .route("/admin/{company}/", get(console::page))
        .route("/admin/{company}/assets/{file}", get(console::asset))
        .route("/admin/{company}/signin", get(signin::signin))
        .route("/admin/{company}/callback", get(callback::callback))
        .route("/admin/{company}/api/me", get(session::me))
        .route("/admin/{company}/signout", post(session::signout))
        .route(
            "/admin/{company}/api/policy/two-factor",
            get(policy::two_factor).put(policy::set_two_factor),
        )
        .route(
            "/admin/{company}/api/users",
            get(users_read::list).post(users::create),
        )
        .route("/admin/{company}/api/users/{user}", get(users_read::one))
        .route("/admin/{company}/api/audit", get(audit::trail))
        .route(
            "/admin/{company}/api/companies",
            get(companies::list).post(companies::create),
        )
        .route(
            "/admin/{company}/api/companies/{id}/suspend",
            post(companies::suspend),
        )
        .route(
            "/admin/{company}/api/companies/{id}/resume",
            post(companies::resume),
        )
        .route(
            "/admin/{company}/api/clients",
            get(clients_read::list).post(clients::register),
        )
        .route(
            "/admin/{company}/api/clients/{client}",
            get(clients_read::one),
        )
        .route("/admin/{company}/api/operators", get(operators::list))
        .route(
            "/admin/{company}/api/operators/{user}/grants/{role}",
            post(operators::grant),
        )
        .route(
            "/admin/{company}/api/operators/{user}/grants/{role}/revoke",
            post(operators::revoke),
        )
        .route(
            "/admin/{company}/api/users/{user}/enrolment",
            post(enrolment::enrol),
        )
        .route(
            "/admin/{company}/api/users/{user}/email/reveal",
            post(users_read::reveal),
        )
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
