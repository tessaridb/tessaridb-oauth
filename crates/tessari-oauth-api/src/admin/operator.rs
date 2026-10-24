//! The operator an admin request comes from, asked for the one role each route needs: either the console session its
//! cookie names, standing only while the issuer session it came from is alive and the operator still holds a role,
//! or a service the company registered, by an assertion it signed for this one request.
//!
//! A service is not a browser: it carries no ambient credential a page could ride on, so it is not held to the
//! console's origin, and an assertion is spent once whatever the request does. It never acts for a person, so the
//! routes that grant authority or show what the console masks are refused to it.

use axum::http::{HeaderMap, header};
use tessari_oauth_core::service_assertion;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::replay::Spent;
use tessari_oauth_types::{Actor, SessionSecret, TenantId, UserId};
use url::Url;

use super::{AdminState, SESSION_COOKIE};
use crate::routes::cookie;
use crate::{Error, Result};

/// The scheme an admin request carries a service's assertion under, in its `Authorization` header.
const SERVICE_SCHEME: &str = "TessariService ";

/// Who is acting on a company's admin API, with the roles they hold now.
pub(super) struct Operator {
    /// The company the console is for.
    pub(super) tenant: TenantId,
    /// An operator in the console, or a registered service.
    pub(super) actor: Actor,
    /// The roles they hold now.
    pub(super) roles: Vec<OperatorRole>,
}

impl Operator {
    /// The console operator's user id; a service is refused, and the refusal recorded, for `action`.
    pub(super) async fn in_console(&self, state: &AdminState, action: &str) -> Result<&UserId> {
        match &self.actor {
            Actor::Operator(user) => Ok(user),
            Actor::Service(_) => {
                state
                    .record(
                        &self.tenant,
                        &AuditEvent {
                            actor: Some(self.actor.name()),
                            action: Some(action.to_owned()),
                            reason: Some("console_only".to_owned()),
                            ..AuditEvent::of(AuditKind::Refused)
                        },
                    )
                    .await;
                Err(Error::ConsoleOnly)
            }
        }
    }

    /// Refuse, and record the refusal, unless this operator holds `role`, which `action` needs.
    pub(super) async fn require(
        &self,
        state: &AdminState,
        role: OperatorRole,
        action: &str,
    ) -> Result<()> {
        if self.roles.contains(&role) {
            return Ok(());
        }
        tracing::warn!(
            event = "console_role_required",
            tenant = self.tenant.as_str(),
            operator = self.actor.name(),
            role = role.name(),
            action,
            "a console request needed a role its operator does not hold"
        );
        state
            .record(
                &self.tenant,
                &AuditEvent {
                    actor: Some(self.actor.name()),
                    role: Some(role),
                    action: Some(action.to_owned()),
                    reason: Some("role_required".to_owned()),
                    ..AuditEvent::of(AuditKind::Refused)
                },
            )
            .await;
        Err(Error::RoleRequired)
    }
}

/// Whether the request carries a service's assertion rather than relying on a console cookie.
pub(super) fn from_service(headers: &HeaderMap) -> bool {
    assertion_in(headers).is_some()
}

/// The service assertion the request's `Authorization` header carries.
fn assertion_in(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(SERVICE_SCHEME))
}

/// The operator of this request at `company`: the service its assertion names, when it carries one, or else the
/// operator of this browser's console session. A session whose issuer session ended, or whose operator holds no role
/// any more, is ended here and answers as no session.
pub(super) async fn signed_in(
    state: &AdminState,
    company: &str,
    headers: &HeaderMap,
) -> Result<Operator> {
    let tenant = company_of(state, company)?;
    if let Some(compact) = assertion_in(headers) {
        return service(state, tenant, compact).await;
    }
    let secret = held(state, headers).ok_or(Error::SessionRequired)?;
    let now = (state.clock)();
    let session = state
        .admin
        .find(&tenant, &secret, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SessionRequired)?;
    let issuer_sessions = state
        .sessions
        .list(&tenant, &session.user, now)
        .await
        .map_err(Error::Store)?;
    let roles = if issuer_sessions.iter().any(|alive| alive.sid == session.sid) {
        state
            .operators
            .grants(&tenant, &session.user, now)
            .await
            .map_err(Error::Store)?
            .into_iter()
            .map(|grant| grant.role)
            .collect()
    } else {
        Vec::new()
    };
    if roles.is_empty() {
        state
            .admin
            .end(&tenant, &secret)
            .await
            .map_err(Error::Store)?;
        return Err(Error::SessionRequired);
    }
    Ok(Operator {
        tenant,
        actor: Actor::Operator(session.user),
        roles,
    })
}

/// The registered service `compact` was signed by, its assertion verified for this company's admin API and spent.
async fn service(state: &AdminState, tenant: TenantId, compact: &str) -> Result<Operator> {
    let named = service_assertion::named_service(compact);
    let credential = match &named {
        Some(id) => state
            .services
            .find(&tenant, id)
            .await
            .map_err(Error::Store)?,
        None => None,
    };
    let Some(credential) = credential else {
        return refuse(state, &tenant, named.map(Actor::Service), "service_unknown").await;
    };
    let actor = Actor::Service(credential.id.clone());
    let console = Url::parse(&state.console).map_err(|_| Error::Internal)?;
    let audience = format!(
        "{}/admin/{}",
        console.origin().ascii_serialization(),
        tenant.as_str()
    );
    let now = (state.clock)();
    let used =
        match service_assertion::verify(compact, &credential.id, &credential.key, &audience, now) {
            Ok(used) => used,
            Err(refusal) => return refuse(state, &tenant, Some(actor), refusal.name()).await,
        };
    let spent = state
        .replay
        .spend_service_assertion(&tenant, &used, now)
        .await
        .map_err(Error::Store)?;
    if spent == Spent::Replayed {
        return refuse(state, &tenant, Some(actor), "service_replayed").await;
    }
    Ok(Operator {
        tenant,
        actor,
        roles: credential.roles,
    })
}

/// Record a refused service assertion under `reason`, by the service it named when it named one, and refuse.
async fn refuse(
    state: &AdminState,
    tenant: &TenantId,
    actor: Option<Actor>,
    reason: &str,
) -> Result<Operator> {
    tracing::warn!(
        event = "service_refused",
        tenant = tenant.as_str(),
        service = actor.as_ref().map(Actor::name),
        reason,
        "an admin request's service assertion was not accepted"
    );
    state
        .record(
            tenant,
            &AuditEvent {
                actor: actor.as_ref().map(Actor::name),
                reason: Some(reason.to_owned()),
                ..AuditEvent::of(AuditKind::Refused)
            },
        )
        .await;
    Err(Error::ServiceRefused)
}

/// Refuse a request that changes state unless it comes from the console's own origin.
pub(super) fn from_console(state: &AdminState, headers: &HeaderMap) -> Result<()> {
    let console = Url::parse(&state.console).map_err(|_| Error::Internal)?;
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|origin| origin.to_str().ok());
    if origin == Some(console.origin().ascii_serialization().as_str()) {
        Ok(())
    } else {
        Err(Error::CrossOrigin)
    }
}

/// The company `company` names, when this node serves it.
pub(super) fn company_of(state: &AdminState, company: &str) -> Result<TenantId> {
    let tenant = TenantId::parse(company).map_err(|_| Error::NotFound)?;
    state.served.issuer(&tenant).ok_or(Error::NotFound)?;
    Ok(tenant)
}

/// The console session secret the request's cookie carries.
pub(super) fn held(state: &AdminState, headers: &HeaderMap) -> Option<SessionSecret> {
    cookie(headers, &state.cookie_name(SESSION_COOKIE)).map(SessionSecret::from_secret)
}
