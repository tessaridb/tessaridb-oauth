//! The sign-in, consent and account pages and their assets: each is served per tenant with its type, byte for byte
//! what the build committed, under a policy that lets it load only its own script, style and image, talk only to
//! this origin, submit no form anywhere and never be framed; anything else under the pages answers 404.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use tessari_oauth_api::public_router;
use tessari_oauth_storage::throttle::Limit;
use tower::ServiceExt;

use crate::routes::{live_storage, state};

const PAGE_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                           connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

const SERVED: [(&str, &str, &str); 8] = [
    ("/acme/login", "text/html; charset=utf-8", "login.html"),
    ("/acme/consent", "text/html; charset=utf-8", "consent.html"),
    ("/acme/account", "text/html; charset=utf-8", "account.html"),
    (
        "/acme/assets/login.js",
        "text/javascript; charset=utf-8",
        "login.js",
    ),
    (
        "/acme/assets/consent.js",
        "text/javascript; charset=utf-8",
        "consent.js",
    ),
    (
        "/acme/assets/account.js",
        "text/javascript; charset=utf-8",
        "account.js",
    ),
    (
        "/acme/assets/pages.css",
        "text/css; charset=utf-8",
        "pages.css",
    ),
    ("/acme/assets/mark.svg", "image/svg+xml", "mark.svg"),
];

fn plenty() -> Limit {
    Limit {
        requests: std::num::NonZeroU64::new(1_000).expect("non-zero"),
        window_secs: std::num::NonZeroU64::new(60).expect("non-zero"),
    }
}

/// GET `path` on the public router: the status, the headers and the body as text.
async fn fetch(path: &str) -> (StatusCode, HeaderMap, String) {
    let storage = live_storage().await;
    let request = Request::get(path)
        .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 50_000))))
        .body(Body::empty())
        .expect("a request");
    let response = public_router(state(&storage, plenty()))
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a body");
    (
        status,
        headers,
        String::from_utf8(bytes.to_vec()).expect("text"),
    )
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .unwrap_or_else(|| panic!("{name} is set"))
        .to_str()
        .expect("ASCII")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_page_and_asset_is_served_as_built_under_the_page_policy() {
    for (path, kind, file) in SERVED {
        let (status, headers, body) = fetch(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(header(&headers, "content-type"), kind, "{path}");
        assert_eq!(
            header(&headers, "content-security-policy"),
            PAGE_POLICY,
            "{path}"
        );
        assert_eq!(header(&headers, "x-content-type-options"), "nosniff");
        assert_eq!(header(&headers, "referrer-policy"), "no-referrer");
        assert_eq!(header(&headers, "cache-control"), "no-cache", "{path}");
        assert!(headers.get("access-control-allow-origin").is_none());
        let built = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("assets")
                .join(file),
        )
        .expect("the committed asset");
        assert!(body == built, "{path} is served byte for byte as built");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_pages_load_only_their_own_assets() {
    for (path, script) in [
        ("/acme/login", "assets/login.js"),
        ("/acme/consent", "assets/consent.js"),
        ("/acme/account", "assets/account.js"),
    ] {
        let (_, _, body) = fetch(path).await;
        assert!(body.contains(&format!("src=\"{script}\"")), "{path}");
        assert!(body.contains("href=\"assets/pages.css\""), "{path}");
        assert!(!body.contains("//"), "{path} names nothing off this origin");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn nothing_else_is_served_under_the_pages() {
    for path in [
        "/acme/assets/other.js",
        "/acme/assets/../login",
        "/acme/assets/",
        "/nobody/login",
        "/nobody/assets/login.js",
    ] {
        let (status, headers, _) = fetch(path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            header(&headers, "content-security-policy"),
            "default-src 'none'; frame-ancestors 'none'",
            "{path} keeps the default policy"
        );
    }
}
