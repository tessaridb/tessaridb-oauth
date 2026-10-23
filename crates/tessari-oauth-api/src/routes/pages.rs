//! `GET /{tenant}/login`, `GET /{tenant}/login/reset`, `GET /{tenant}/consent`, `GET /{tenant}/account` and
//! `GET /{tenant}/assets/*`: the sign-in, password-reset, consent and account pages.
//!
//! They carry no data and need no session: everything a page shows it asks of the sign-in or account API from the
//! browser that holds the sign-in or the session. Each answer carries a policy that lets the page run only its own
//! script and style, show only its own image, talk only to this origin, submit no form anywhere, rewrite no base
//! address and never be framed.
//! The pages link their assets relatively, so a page served under a tenant loads that tenant's copy; the reset page
//! sits under the sign-in page and links them one level up.
//!
//! The bytes are the committed output of `pages/` (`npm run build`), embedded so that building the server never
//! needs Node; `npm run verify` fails when the committed output no longer matches its source.

use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use axum::http::{HeaderValue, Uri};
use axum::response::{IntoResponse, Response};

use crate::state::PublicState;
use crate::{Error, Result};

/// What a page may load and do.
pub(super) const POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                      connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

/// One served file: the path under the tenant, its type, its bytes.
type Asset = (&'static str, &'static str, &'static str);

pub(super) const ASSETS: [Asset; 10] = [
    (
        "/login",
        "text/html; charset=utf-8",
        include_str!("../../assets/login.html"),
    ),
    (
        "/login/reset",
        "text/html; charset=utf-8",
        include_str!("../../assets/reset.html"),
    ),
    (
        "/consent",
        "text/html; charset=utf-8",
        include_str!("../../assets/consent.html"),
    ),
    (
        "/account",
        "text/html; charset=utf-8",
        include_str!("../../assets/account.html"),
    ),
    (
        "/assets/login.js",
        "text/javascript; charset=utf-8",
        include_str!("../../assets/login.js"),
    ),
    (
        "/assets/reset.js",
        "text/javascript; charset=utf-8",
        include_str!("../../assets/reset.js"),
    ),
    (
        "/assets/consent.js",
        "text/javascript; charset=utf-8",
        include_str!("../../assets/consent.js"),
    ),
    (
        "/assets/account.js",
        "text/javascript; charset=utf-8",
        include_str!("../../assets/account.js"),
    ),
    (
        "/assets/pages.css",
        "text/css; charset=utf-8",
        include_str!("../../assets/pages.css"),
    ),
    (
        "/assets/mark.svg",
        "image/svg+xml",
        include_str!("../../assets/mark.svg"),
    ),
];

pub(super) async fn asset(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
    uri: Uri,
) -> Result<Response> {
    state.tenant(&tenant)?;
    let served = uri
        .path()
        .strip_prefix('/')
        .and_then(|path| path.strip_prefix(tenant.as_str()))
        .ok_or(Error::NotFound)?;
    let (_, kind, body) = ASSETS
        .iter()
        .find(|(path, _, _)| *path == served)
        .ok_or(Error::NotFound)?;
    let mut response = (*body).into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(kind));
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(POLICY));
    // Revalidated on every load, so a new release's pages are never mixed with an old one's script.
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(response)
}
