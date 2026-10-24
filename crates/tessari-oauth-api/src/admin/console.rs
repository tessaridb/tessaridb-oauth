//! `GET /admin/{company}/` and `GET /admin/{company}/assets/{file}`: the console's page and its assets.
//!
//! They carry no data and need no session: everything the page shows it asks of the console API from the browser
//! that holds the console session, and a browser without one is offered the company's sign-in. Each answer carries
//! the pages' policy, so the console runs only its own script and style, shows only its own image, talks only to
//! this origin, submits no form anywhere and is never framed. A company this node does not serve answers 404.
//!
//! The bytes are the committed output of `pages/` (`npm run build`), embedded so that building the server never
//! needs Node.

use axum::extract::{Path, State};
use axum::http::HeaderValue;
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};

use super::AdminState;
use super::operator::company_of;
use crate::{Error, Result};

/// What the page may load and do; the same policy the sign-in pages carry.
const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                      connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

/// The page's type and bytes.
const PAGE: (&str, &str) = (
    "text/html; charset=utf-8",
    include_str!("../../assets/console.html"),
);

/// One asset: its file name under `assets/`, its type, its bytes.
type Asset = (&'static str, &'static str, &'static str);

const ASSETS: [Asset; 4] = [
    (
        "console.js",
        "text/javascript; charset=utf-8",
        include_str!("../../assets/console.js"),
    ),
    (
        "console.css",
        "text/css; charset=utf-8",
        include_str!("../../assets/console.css"),
    ),
    (
        "pages.css",
        "text/css; charset=utf-8",
        include_str!("../../assets/pages.css"),
    ),
    (
        "mark.svg",
        "image/svg+xml",
        include_str!("../../assets/mark.svg"),
    ),
];

/// The console page of `company`.
pub(super) async fn page(
    State(state): State<AdminState>,
    Path(company): Path<String>,
) -> Result<Response> {
    company_of(&state, &company)?;
    Ok(served(PAGE))
}

/// The asset `file` of `company`'s console.
pub(super) async fn asset(
    State(state): State<AdminState>,
    Path((company, file)): Path<(String, String)>,
) -> Result<Response> {
    company_of(&state, &company)?;
    let (_, kind, body) = ASSETS
        .iter()
        .find(|(name, _, _)| *name == file)
        .ok_or(Error::NotFound)?;
    Ok(served((kind, body)))
}

/// `body` answered as `kind` under the page policy.
fn served((kind, body): (&'static str, &'static str)) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(kind));
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(POLICY));
    response
}
