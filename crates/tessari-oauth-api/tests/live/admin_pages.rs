//! The admin console's page and its assets: served on the admin listener for a company it serves, byte for byte what
//! the build committed, under a policy that lets the page load only its own script, style and image, talk only to
//! this origin, submit no form anywhere and never be framed. They carry no data and need no session; anything else
//! under them, and any company the node does not serve, answers 404.

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use tessari_oauth_api::{AdminState, admin_router};
use tower::ServiceExt;

use crate::admin_signin::console_state;
use crate::token_fixture::server;

const PAGE_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                           connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

const SERVED: [(&str, &str, &str); 5] = [
    ("/admin/acme/", "text/html; charset=utf-8", "console.html"),
    (
        "/admin/acme/assets/console.js",
        "text/javascript; charset=utf-8",
        "console.js",
    ),
    (
        "/admin/acme/assets/console.css",
        "text/css; charset=utf-8",
        "console.css",
    ),
    (
        "/admin/acme/assets/pages.css",
        "text/css; charset=utf-8",
        "pages.css",
    ),
    ("/admin/acme/assets/mark.svg", "image/svg+xml", "mark.svg"),
];

/// GET `path` on the admin router over `state`: the status, the headers and the body as text.
async fn fetch(state: &AdminState, path: &str) -> (StatusCode, HeaderMap, String) {
    let response = admin_router(state.clone())
        .oneshot(Request::get(path).body(Body::empty()).expect("a request"))
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
async fn the_console_page_and_its_assets_are_served_as_built_under_the_page_policy() {
    let server = server(2).await;
    let state = console_state(&server, "https://admin.example.com");
    for (path, kind, file) in SERVED {
        let (status, headers, body) = fetch(&state, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(header(&headers, "content-type"), kind, "{path}");
        assert_eq!(
            header(&headers, "content-security-policy"),
            PAGE_POLICY,
            "{path}"
        );
        assert_eq!(header(&headers, "x-content-type-options"), "nosniff");
        assert_eq!(header(&headers, "cache-control"), "no-store", "{path}");
        let built = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("assets")
                .join(file),
        )
        .expect("the committed asset");
        assert!(body == built, "{path} is served byte for byte as built");
    }
    let (_, _, page) = fetch(&state, "/admin/acme/").await;
    assert!(page.contains("src=\"assets/console.js\""));
    assert!(page.contains("href=\"assets/console.css\""));
    assert!(
        !page.contains("//"),
        "the page names nothing off this origin"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn nothing_else_is_served_under_the_console() {
    let server = server(2).await;
    let state = console_state(&server, "https://admin.example.com");
    for path in [
        "/admin/acme/assets/login.js",
        "/admin/acme/assets/../api/me",
        "/admin/acme/assets/",
        "/admin/nowhere/",
        "/admin/nowhere/assets/console.js",
    ] {
        let (status, headers, _) = fetch(&state, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            header(&headers, "content-security-policy"),
            "default-src 'none'; frame-ancestors 'none'",
            "{path} keeps the default policy"
        );
    }
}
