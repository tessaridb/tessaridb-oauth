//! The headers every public answer carries, refusals included: no sniffing, no referrer, nothing may frame or load
//! from a JSON document, and HTTPS only. A page sets its own policy, which is kept; every other answer gets this one.

use axum::http::{HeaderName, HeaderValue, header};
use axum::response::Response;

const FIXED: [(HeaderName, &str); 4] = [
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::REFERRER_POLICY, "no-referrer"),
    (
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'",
    ),
    // Two years; the issuer is an https URL by construction, so every host serving it is HTTPS-only.
    (
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=63072000; includeSubDomains",
    ),
];

/// Mark `response` as never to be stored by any cache (RFC 6749 §5.1).
pub(crate) fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// Set the fixed headers on `response`, replacing any a handler set, except a page's own content policy.
pub(crate) fn protect(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in FIXED {
        if name == header::CONTENT_SECURITY_POLICY && headers.contains_key(&name) {
            continue;
        }
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}
