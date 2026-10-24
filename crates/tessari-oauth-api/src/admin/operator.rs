//! The operator a console request comes from: the console session its cookie names, standing only while the issuer
//! session it came from is alive and the operator still holds a role, and asked for the one role each route needs.

use axum::http::{HeaderMap, header};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{SessionSecret, TenantId, UserId};
use url::Url;

use super::{AdminState, SESSION_COOKIE};
use crate::routes::cookie;
use crate::{Error, Result};

/// An operator signed in to a company's console, with the roles they hold now.
pub(super) struct Operator {
    /// The company the console is for.
    pub(super) tenant: TenantId,
    /// The operator's user id.
    pub(super) user: UserId,
    /// The roles they hold now.
    pub(super) roles: Vec<OperatorRole>,
}

impl Operator {
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
            operator = self.user.as_str(),
            role = role.name(),
            action,
            "a console request needed a role its operator does not hold"
        );
        state
            .record(
                &self.tenant,
                &AuditEvent {
                    actor: Some(self.user.as_str().to_owned()),
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

/// The operator of this browser's console session at `company`. A session whose issuer session ended, or whose
/// operator holds no role any more, is ended here and answers as no session.
pub(super) async fn signed_in(
    state: &AdminState,
    company: &str,
    headers: &HeaderMap,
) -> Result<Operator> {
    let tenant = company_of(state, company)?;
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
        user: session.user,
        roles,
    })
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
