//! The console session after sign-in: `GET /admin/{company}/api/me` answers for its operator only while the issuer
//! session it came from is alive and the operator still holds a current grant, and ends it otherwise;
//! `POST /admin/{company}/signout` ends it for a request from the console's own origin.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tessari_oauth_storage::admin::AdminSession;
use tessari_oauth_types::{SessionSecret, TenantId};
use url::Url;

use super::{AdminState, SESSION_COOKIE};
use crate::routes::cookie;
use crate::{Error, Result};

/// Who the console is signed in as.
#[derive(Serialize)]
struct Me {
    /// The operator's user id.
    user: String,
    /// The roles they hold now.
    roles: Vec<&'static str>,
}

/// The operator of this browser's console session, and the roles they hold now.
pub(super) async fn me(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let tenant = company_of(&state, &company)?;
    let secret = held(&state, &headers).ok_or(Error::SessionRequired)?;
    let now = (state.clock)();
    let session = state
        .admin
        .find(&tenant, &secret, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SessionRequired)?;
    let roles = match standing(&state, &tenant, &session).await? {
        Some(roles) => roles,
        None => {
            state
                .admin
                .end(&tenant, &secret)
                .await
                .map_err(Error::Store)?;
            return Err(Error::SessionRequired);
        }
    };
    Ok(Json(Me {
        user: session.user.as_str().to_owned(),
        roles,
    })
    .into_response())
}

/// End this browser's console session, when the request comes from the console itself.
pub(super) async fn signout(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let tenant = company_of(&state, &company)?;
    let console = Url::parse(&state.console).map_err(|_| Error::Internal)?;
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|origin| origin.to_str().ok());
    if origin != Some(console.origin().ascii_serialization().as_str()) {
        return Err(Error::CrossOrigin);
    }
    if let Some(secret) = held(&state, &headers) {
        state
            .admin
            .end(&tenant, &secret)
            .await
            .map_err(Error::Store)?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        state.cookie(SESSION_COOKIE, "", "Strict", 0)?,
    );
    Ok(response)
}

/// The company `company` names, when this node serves it.
fn company_of(state: &AdminState, company: &str) -> Result<TenantId> {
    let tenant = TenantId::parse(company).map_err(|_| Error::NotFound)?;
    state.served.issuer(&tenant).ok_or(Error::NotFound)?;
    Ok(tenant)
}

/// The console session secret the request's cookie carries.
fn held(state: &AdminState, headers: &HeaderMap) -> Option<SessionSecret> {
    cookie(headers, &state.cookie_name(SESSION_COOKIE)).map(SessionSecret::from_secret)
}

/// The roles `session`'s operator holds now, when the issuer session it came from is still alive and they hold any.
async fn standing(
    state: &AdminState,
    tenant: &TenantId,
    session: &AdminSession,
) -> Result<Option<Vec<&'static str>>> {
    let now = (state.clock)();
    let issuer_sessions = state
        .sessions
        .list(tenant, &session.user, now)
        .await
        .map_err(Error::Store)?;
    if !issuer_sessions.iter().any(|alive| alive.sid == session.sid) {
        return Ok(None);
    }
    let grants = state
        .operators
        .grants(tenant, &session.user, now)
        .await
        .map_err(Error::Store)?;
    if grants.is_empty() {
        return Ok(None);
    }
    Ok(Some(grants.iter().map(|grant| grant.role.name()).collect()))
}
