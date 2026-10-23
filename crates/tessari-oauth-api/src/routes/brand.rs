//! `GET /{tenant}/assets/brand.css`, `/assets/brand.json` and `/assets/logo.png`: a company's brand as the public
//! pages read it, under the same policy as the pages themselves.
//!
//! Nothing here is markup. The stylesheet holds two colour tokens written from a validated `#rrggbb`, the JSON holds
//! the name and links as strings for the pages to set as text and as https addresses, and the image is the PNG the
//! server re-encoded at upload. Without a brand the stylesheet sets no token, so the pages keep the house colours.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use super::pages::POLICY;
use crate::state::PublicState;
use crate::{Error, Result};

/// The brand as the pages read it; each field null when unset.
#[derive(Serialize)]
struct Shown<'a> {
    name: Option<&'a str>,
    support: Option<&'a str>,
    privacy: Option<&'a str>,
    /// Unix seconds of the logo's upload, which the pages put in the logo's address so a new one is fetched anew.
    logo: Option<u64>,
}

/// `response` with `kind` and the headers every page asset carries.
fn served(mut response: Response, kind: &'static str) -> Response {
    let headers: &mut HeaderMap = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(kind));
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(POLICY));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// The company's colour tokens: the accent, and the same colour at an eighth opacity for washes.
pub(super) async fn css(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let brand = state.brands.find(&tenant).await.map_err(Error::Store)?;
    let body = brand.map_or_else(
        || "/* No company brand is set; the pages keep their own colours. */\n".to_owned(),
        |brand| {
            let accent = brand.accent.as_str();
            format!(":root {{\n  --brand-accent: {accent};\n  --brand-wash: {accent}1f;\n}}\n")
        },
    );
    Ok(served(body.into_response(), "text/css; charset=utf-8"))
}

/// The company's name, links and whether it has a logo.
pub(super) async fn json(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let brand = state.brands.find(&tenant).await.map_err(Error::Store)?;
    let logo = state
        .brands
        .logo_updated(&tenant)
        .await
        .map_err(Error::Store)?;
    let shown = Shown {
        name: brand.as_ref().map(|brand| brand.name.as_str()),
        support: brand
            .as_ref()
            .and_then(|brand| brand.support.as_ref())
            .map(|link| link.as_str()),
        privacy: brand
            .as_ref()
            .and_then(|brand| brand.privacy.as_ref())
            .map(|link| link.as_str()),
        logo: logo.map(|at| at.unix_secs()),
    };
    Ok(served(Json(shown).into_response(), "application/json"))
}

/// The company's logo, or 404 when it has none.
pub(super) async fn logo(
    State(state): State<PublicState>,
    Path(tenant): Path<String>,
) -> Result<Response> {
    let (tenant, _) = state.tenant(&tenant)?;
    let png = state
        .brands
        .logo(&tenant)
        .await
        .map_err(Error::Store)?
        .ok_or(Error::NotFound)?;
    Ok(served(png.into_response(), "image/png"))
}
