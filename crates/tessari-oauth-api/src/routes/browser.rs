//! The browser cookie: a 256-bit value this server draws the first time a browser brings an authorization request, and
//! keeps reading after. A pending authorization records its digest, so the sign-in, the consent and the code that
//! follow are answered only to the browser that began it; a request id copied into another browser names nothing there.

use axum::http::{HeaderMap, HeaderValue};
use tessari_oauth_constants::{BROWSER_COOKIE, INTERACTION_TTL_SECS};
use tessari_oauth_infrastructure::custody::random_secret;
use tessari_oauth_types::{BrowserBinding, base64url};

use super::login::cookie;
use crate::{Error, Result};

/// The binding the request's browser cookie carries, when it carries one that could be this server's.
pub(super) fn held(headers: &HeaderMap) -> Option<BrowserBinding> {
    cookie(headers, BROWSER_COOKIE).map(BrowserBinding::from_secret)
}

/// The binding the request's browser holds, or a fresh one drawn now when it holds none.
pub(super) fn held_or_drawn(headers: &HeaderMap) -> Result<BrowserBinding> {
    if let Some(binding) = held(headers) {
        return Ok(binding);
    }
    let drawn = random_secret().map_err(|_| Error::Internal)?;
    Ok(BrowserBinding::from_secret(base64url::encode(&drawn)))
}

/// The cookie that keeps `binding` in the browser for as long as a pending authorization lives.
pub(super) fn browser_cookie(binding: &BrowserBinding) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{BROWSER_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={INTERACTION_TTL_SECS}",
        binding.expose()
    ))
    .map_err(|_| Error::Internal)
}
