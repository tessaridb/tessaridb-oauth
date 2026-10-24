//! A company's client registrations read in its console by an operator holding `clients`: a page at a time in id order
//! behind a cursor and with no total, or the one registration an id names, with how many users hold a grant to it.
//! The server's own console client is shown and marked as such; nothing about a client is secret, since the console
//! registers no shared secrets.

use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tessari_oauth_constants::{ADMIN_CONSOLE_CLIENT, CLIENT_PAGE_DEFAULT, CLIENT_PAGE_MAX};
use tessari_oauth_core::clients::{AuthMethod, ClientRegistration};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::ClientId;

use super::AdminState;
use super::change::Refusal;
use super::operator::signed_in;
use crate::{Error, Result};

/// The read the routes below name when it is refused.
const READ: &str = "clients.read";

/// What a list asks for: a page after a client.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Listing {
    after: Option<String>,
    limit: Option<u32>,
}

/// One registration as the console shows it.
#[derive(Serialize)]
pub(super) struct Shown {
    client_id: String,
    kind: &'static str,
    auth_method: &'static str,
    assertion_alg: Option<&'static str>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    backchannel_logout_uri: Option<String>,
    scope_ceiling: Vec<String>,
    resources: Vec<String>,
    grant_types: Vec<&'static str>,
    dpop_bound_access_tokens: bool,
    keys: usize,
    sector: Option<String>,
    console: bool,
}

/// One registration with how many users hold a standing grant to it.
#[derive(Serialize)]
struct Held {
    #[serde(flatten)]
    client: Shown,
    holders: usize,
}

/// A page of registrations, and the cursor of the next one when this one is full.
#[derive(Serialize)]
struct Page {
    clients: Vec<Shown>,
    next: Option<String>,
}

/// The company's registrations, a page after `after`.
pub(super) async fn list(
    State(state): State<AdminState>,
    Path(company): Path<String>,
    headers: HeaderMap,
    listing: std::result::Result<Query<Listing>, QueryRejection>,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator
        .require(&state, OperatorRole::Clients, READ)
        .await?;
    let Query(listing) = listing.map_err(|_| Error::Invalid)?;
    let limit = listing.limit.unwrap_or(CLIENT_PAGE_DEFAULT);
    if !(1..=CLIENT_PAGE_MAX).contains(&limit) {
        return Err(Error::Invalid);
    }
    let after = listing
        .after
        .map(|after| ClientId::parse(after).map_err(|_| Error::Invalid))
        .transpose()?;
    let registrations = state
        .clients
        .page(&operator.tenant, after.as_ref(), limit)
        .await
        .map_err(Error::Store)?;
    let full = u32::try_from(registrations.len()).is_ok_and(|count| count == limit);
    let next = registrations
        .last()
        .filter(|_| full)
        .map(|client| client.client_id.as_str().to_owned());
    let clients = registrations.iter().map(shown).collect();
    Ok(Json(Page { clients, next }).into_response())
}

/// The company's registration `client`.
pub(super) async fn one(
    State(state): State<AdminState>,
    Path((company, client)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response> {
    let operator = signed_in(&state, &company, &headers).await?;
    operator
        .require(&state, OperatorRole::Clients, READ)
        .await?;
    let found = match ClientId::parse(client) {
        Ok(client) => state
            .clients
            .find(&operator.tenant, &client)
            .await
            .map_err(Error::Store)?,
        Err(_) => None,
    };
    let Some(client) = found else {
        return Ok(missing());
    };
    let holders = state
        .consents
        .holders(&operator.tenant, &client.client_id)
        .await
        .map_err(Error::Store)?;
    Ok(Json(Held {
        client: shown(&client),
        holders,
    })
    .into_response())
}

/// The answer for a client the company has not registered.
fn missing() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(Refusal {
            code: "client_not_found",
            message: "this company has no such client",
        }),
    )
        .into_response()
}

/// `client` as the console shows it.
pub(super) fn shown(client: &ClientRegistration) -> Shown {
    let assertion_alg = match client.auth_method {
        AuthMethod::PrivateKeyJwt(algorithm) => Some(algorithm.name()),
        _ => None,
    };
    let texts = |uris: &[tessari_oauth_types::RedirectUri]| {
        uris.iter().map(|uri| uri.as_str().to_owned()).collect()
    };
    Shown {
        client_id: client.client_id.as_str().to_owned(),
        kind: if client.auth_method == AuthMethod::None {
            "public"
        } else {
            "confidential"
        },
        auth_method: client.auth_method.name(),
        assertion_alg,
        redirect_uris: texts(&client.redirect_uris),
        post_logout_redirect_uris: texts(&client.post_logout_redirect_uris),
        backchannel_logout_uri: client
            .backchannel_logout_uri
            .as_ref()
            .map(|uri| uri.as_str().to_owned()),
        scope_ceiling: client.scope_ceiling.iter().map(str::to_owned).collect(),
        resources: client
            .resources
            .iter()
            .map(|resource| resource.as_str().to_owned())
            .collect(),
        grant_types: client
            .grant_types
            .iter()
            .map(|grant| grant.name())
            .collect(),
        dpop_bound_access_tokens: client.dpop_bound_access_tokens,
        keys: client.keys.len(),
        sector: client
            .sector
            .as_ref()
            .map(|sector| sector.as_str().to_owned()),
        console: client.client_id.as_str() == ADMIN_CONSOLE_CLIENT,
    }
}
