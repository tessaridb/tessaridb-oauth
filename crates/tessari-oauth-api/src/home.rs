//! Requests for a company another region serves: answered `307 Temporary Redirect` to the same path and query at
//! that region's public base URL, so the method and body are sent again there. A company this node serves, and a
//! path that names no company another region serves, go on to the routes, which answer the second with 404.
//!
//! The target is the base URL the company's own region recorded, followed by the request's path, which begins with
//! the company id: the host is never taken from the request.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::LOCATION;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tessari_oauth_storage::companies::{Elsewhere, Served};
use tessari_oauth_types::TenantId;

/// What deciding where a request belongs reads.
#[derive(Clone)]
pub(crate) struct Homes {
    /// The companies this node serves.
    pub(crate) served: Arc<Served>,
    /// The companies other regions serve, with their regions' base URLs.
    pub(crate) elsewhere: Arc<Elsewhere>,
}

/// Send a request for a company another region serves to that region.
pub(crate) async fn send_home(
    State(homes): State<Homes>,
    request: Request,
    next: Next,
) -> Response {
    match home(&homes, &request) {
        Some(location) => (StatusCode::TEMPORARY_REDIRECT, [(LOCATION, location)]).into_response(),
        None => next.run(request).await,
    }
}

/// Where `request` belongs when that is another region: its base URL, the path and the query.
fn home(homes: &Homes, request: &Request) -> Option<HeaderValue> {
    let uri = request.uri();
    let segment = uri.path().strip_prefix('/')?.split('/').next()?;
    let company = TenantId::parse(segment).ok()?;
    if homes.served.issuer(&company).is_some() {
        return None;
    }
    let base = homes.elsewhere.home(&company)?;
    let target = uri
        .path_and_query()
        .map_or(uri.path(), |path| path.as_str());
    HeaderValue::try_from(format!("{base}{target}")).ok()
}

#[cfg(test)]
#[path = "home_tests.rs"]
mod tests;
