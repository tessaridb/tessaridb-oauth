//! A company's audit trail read in its console by an operator holding `audit`: in order, a page at a time behind the
//! positions, each message with only the fields it was written with.

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::AUDIT_PAGE_MAX;
use tessari_oauth_storage::audit::AuditRecord;
use tessari_oauth_storage::operators::OperatorRole;

use super::AdminState;
use super::operator::signed_in;
use crate::{Error, Result};

/// The read the route names when it is refused.
const READ: &str = "audit.read";

/// A page asked for: after a position, and how many.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Listing {
    after: Option<u64>,
    limit: Option<u64>,
}

/// One message as the console shows it; a field the message was not written with is left out.
#[derive(Serialize)]
struct Shown {
    position: u64,
    at: u64,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bound_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    families: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
}

/// A page of messages, and the position to read after next when this page is full.
#[derive(Serialize)]
struct Page {
    events: Vec<Shown>,
    next: Option<u64>,
}

/// The company's trail after `after`.
pub(super) async fn trail(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    listing: std::result::Result<Query<Listing>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator.require(&state, OperatorRole::Audit, READ).await?;
    let Query(listing) = listing.map_err(|_| Error::Invalid)?;
    let limit = listing.limit.unwrap_or(AUDIT_PAGE_MAX);
    if !(1..=AUDIT_PAGE_MAX).contains(&limit) {
        return Err(Error::Invalid);
    }
    let records = state
        .audit
        .read_after(&operator.tenant, listing.after.unwrap_or(0), limit)
        .await
        .map_err(Error::Store)?;
    let full = u64::try_from(records.len()).is_ok_and(|count| count == limit);
    let next = records
        .last()
        .filter(|_| full)
        .map(|record| record.position);
    let events = records.into_iter().map(shown).collect();
    Ok(Json(Page { events, next }).into_response())
}

/// `record` as the console shows it.
fn shown(record: AuditRecord) -> Shown {
    let event = record.event;
    Shown {
        position: record.position,
        at: record.at.unix_secs(),
        kind: event.kind.as_str(),
        client_id: event.client_id.map(|client| client.as_str().to_owned()),
        user: event.user.map(|user| user.as_str().to_owned()),
        subject: event.subject,
        scopes: event
            .scopes
            .map(|scopes| scopes.iter().map(str::to_owned).collect()),
        audience: event.audience,
        jti: event.jti,
        auth_method: event.auth_method,
        bound_to: event.bound_to.map(|key| key.as_str().to_owned()),
        reason: event.reason,
        families: event.families,
        actor: event.actor,
        role: event.role.map(OperatorRole::name),
        action: event.action,
    }
}
