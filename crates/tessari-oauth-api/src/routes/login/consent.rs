//! `GET` and `POST /{tenant}/login/api/consent`: the user's answer to what a pending authorization asks.
//!
//! Both need the session this issuer opened for the browser, and a request still pending that this browser brought. The page is told what is
//! asked and not yet granted under the consent policy in force, and nothing else: the client by its registered id,
//! never a name the client supplied. Allowing records the grant before any code exists, widening the user's standing
//! grant to the client, and then takes the request once and answers the address of its redirect URI with a code.
//! Denying takes the request, grants nothing and answers the redirect URI with `access_denied`, its `state` and the
//! issuer (RFC 6749 §4.1.2.1, RFC 9207). Either answer is the address for the page to send the browser to.

use axum::Json;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::{CONSENT_POLICY_VERSION, CONSENT_SHOWN_VERSION, SESSION_COOKIE};
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_core::consents::{ConsentRequest, Coverage};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::consents::NewGrant;
use tessari_oauth_storage::sessions::Session;
use tessari_oauth_types::{BrowserBinding, ErrorCode, SessionSecret, TenantId, Timestamp};

use super::super::browser::held;
use super::super::resume::issued;
use super::{body, cookie, record, well_formed};
use crate::state::PublicState;
use crate::{Error, Result};

#[derive(Deserialize)]
pub(in crate::routes) struct Asked {
    interaction: Option<String>,
}

/// What is asked and not yet granted.
#[derive(Serialize)]
struct Delta {
    client_id: String,
    scopes: Vec<String>,
    resources: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Decision {
    Allow,
    Deny,
}

#[derive(Deserialize)]
pub(in crate::routes) struct Answered {
    interaction: String,
    decision: Decision,
}

/// Where the page sends the browser next.
#[derive(Serialize)]
struct Onward {
    redirect: String,
}

pub(in crate::routes) async fn consent(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    query: std::result::Result<Query<Asked>, QueryRejection>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let now = (state.clock)();
    let id = query
        .ok()
        .and_then(|Query(asked)| asked.interaction)
        .ok_or(Error::Invalid)?;
    let browser = held(&headers).ok_or(Error::SigninGone)?;
    let request = pending(&state, &tenant, (&id, &browser), now).await?;
    let user = signed_in(&state, &tenant, &headers, now).await?.user;
    let coverage = state
        .consents
        .check(
            &tenant,
            &user,
            &request.client_id,
            &asked(&request),
            CONSENT_POLICY_VERSION,
        )
        .await
        .map_err(Error::Store)?;
    let (scopes, resources) = match coverage {
        Coverage::Covered => (Vec::new(), Vec::new()),
        Coverage::Prompt { scopes, resources } => (
            scopes
                .map(|scopes| scopes.iter().map(str::to_owned).collect())
                .unwrap_or_default(),
            resources
                .iter()
                .map(|resource| resource.as_str().to_owned())
                .collect(),
        ),
    };
    let delta = Delta {
        client_id: request.client_id.as_str().to_owned(),
        scopes,
        resources,
    };
    Ok((StatusCode::OK, Json(delta)).into_response())
}

pub(in crate::routes) async fn decide(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    read: std::result::Result<Json<Answered>, JsonRejection>,
) -> Result<Response> {
    let (tenant, issuer) = state.tenant(&tenant)?;
    let answered = body(read)?;
    let now = (state.clock)();
    let browser = held(&headers).ok_or(Error::SigninGone)?;
    let request = pending(&state, &tenant, (&answered.interaction, &browser), now).await?;
    let session = signed_in(&state, &tenant, &headers, now).await?;
    let user = session.user.clone();
    let target = match answered.decision {
        Decision::Allow => {
            let grant = NewGrant {
                tenant: tenant.clone(),
                user: user.clone(),
                client_id: request.client_id.clone(),
                request: asked(&request),
                policy_version: CONSENT_POLICY_VERSION,
                shown_version: CONSENT_SHOWN_VERSION.to_owned(),
                at: now,
            };
            state.consents.grant(&grant).await.map_err(Error::Store)?;
            let event = AuditEvent {
                client_id: Some(request.client_id),
                user: Some(user.clone()),
                scopes: Some(request.scopes),
                ..AuditEvent::of(AuditKind::Consented)
            };
            record(&state, &tenant, &event, now).await;
            issued(
                &state,
                &tenant,
                issuer,
                (&answered.interaction, &browser),
                session,
                now,
            )
            .await?
        }
        Decision::Deny => {
            let taken = state
                .interactions
                .finish(&tenant, &answered.interaction, &browser, now)
                .await
                .map_err(Error::Store)?;
            taken.map(|request| denied(&request, issuer)).transpose()?
        }
    };
    let redirect = target.ok_or(Error::SigninGone)?;
    Ok((StatusCode::OK, Json(Onward { redirect })).into_response())
}

/// The request `id` names in `tenant`, still pending at `now` and brought by `browser`: [`Error::Invalid`] for an id this server could not
/// have made, [`Error::SigninGone`] for one that is answered, lapsed or never kept.
async fn pending(
    state: &PublicState,
    tenant: &TenantId,
    (id, browser): (&str, &BrowserBinding),
    now: Timestamp,
) -> Result<AuthorizationRequest> {
    if !well_formed(id) {
        return Err(Error::Invalid);
    }
    state
        .interactions
        .find(tenant, id, browser, now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SigninGone)
}

/// The session the request's cookie names in `tenant` at `now`.
async fn signed_in(
    state: &PublicState,
    tenant: &TenantId,
    headers: &HeaderMap,
    now: Timestamp,
) -> Result<Session> {
    let Some(value) = cookie(headers, SESSION_COOKIE) else {
        return Err(Error::SessionRequired);
    };
    state
        .sessions
        .find(tenant, &SessionSecret::from_secret(value), now)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::SessionRequired)
}

/// What `request` asks to be granted.
fn asked(request: &AuthorizationRequest) -> ConsentRequest {
    ConsentRequest {
        scopes: request.scopes.clone(),
        resources: request.resources.clone(),
    }
}

/// The address of `request`'s redirect URI refusing it as denied by the user, from `issuer`.
fn denied(request: &AuthorizationRequest, issuer: &str) -> Result<String> {
    let mut target = url::Url::parse(&request.redirect_uri).map_err(|_| Error::Internal)?;
    {
        let mut query = target.query_pairs_mut();
        query.append_pair("error", ErrorCode::AccessDenied.as_str());
        if let Some(state) = &request.state {
            query.append_pair("state", state);
        }
        query.append_pair("iss", issuer);
    }
    Ok(target.into())
}
