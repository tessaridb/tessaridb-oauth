//! The headers every public answer carries, refusals included: no sniffing, no referrer, nothing may frame or load
//! from a JSON document, and HTTPS only.

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

/// Set the fixed headers on `response`, replacing any a handler set.
pub(crate) fn protect(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in FIXED {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}
