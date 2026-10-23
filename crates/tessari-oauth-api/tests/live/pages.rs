//! The sign-in, consent and account pages and their assets: each is served per tenant with its type, byte for byte
//! what the build committed, under a policy that lets it load only its own script, style and image, talk only to
//! this origin, submit no form anywhere and never be framed; anything else under the pages answers 404.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use tessari_oauth_api::public_router;
use tessari_oauth_core::branding::{Accent, BrandLink, BrandName};
use tessari_oauth_core::logo::reencode;
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::brands::Brand;
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_types::{TenantId, Timestamp};
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
    let (status, headers, bytes) = fetch_from(&storage, path).await;
    (status, headers, String::from_utf8(bytes).expect("text"))
}

/// GET `path` on the public router over `storage`: the status, the headers and the body's bytes.
async fn fetch_from(storage: &Storage, path: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
    let request = Request::get(path)
        .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 7], 50_000))))
        .body(Body::empty())
        .expect("a request");
    let response = public_router(state(storage, plenty()))
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a body");
    (status, headers, bytes.to_vec())
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
        assert!(body.contains("href=\"assets/brand.css\""), "{path}");
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

/// Assert the headers every brand asset carries: `kind`, the page policy, nosniff and revalidation.
fn assert_brand_headers(headers: &HeaderMap, kind: &str, path: &str) {
    assert_eq!(header(headers, "content-type"), kind, "{path}");
    assert_eq!(
        header(headers, "content-security-policy"),
        PAGE_POLICY,
        "{path}"
    );
    assert_eq!(
        header(headers, "x-content-type-options"),
        "nosniff",
        "{path}"
    );
    assert_eq!(header(headers, "cache-control"), "no-cache", "{path}");
}

/// A one-pixel PNG as the server keeps it.
fn logo() -> tessari_oauth_core::logo::Png {
    let mut sent = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut sent, 1, 1);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("a header");
        writer
            .write_image_data(&[10, 20, 30, 255])
            .expect("a pixel");
    }
    reencode(&sent).expect("a logo")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_brand_assets_carry_the_house_brand_until_a_company_sets_one() {
    let storage = live_storage().await;
    let acme = TenantId::parse("acme").expect("a tenant id");
    storage.tenants.provision(&acme).await.expect("provisioned");
    let (status, headers, css) = fetch_from(&storage, "/acme/assets/brand.css").await;
    assert_eq!(status, StatusCode::OK);
    assert_brand_headers(&headers, "text/css; charset=utf-8", "brand.css");
    assert!(
        !String::from_utf8(css)
            .expect("text")
            .contains("--brand-accent")
    );
    let (status, headers, json) = fetch_from(&storage, "/acme/assets/brand.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_brand_headers(&headers, "application/json", "brand.json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&json).expect("json"),
        serde_json::json!({ "name": null, "support": null, "privacy": null, "logo": null })
    );
    let (status, _, _) = fetch_from(&storage, "/acme/assets/logo.png").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "no logo, nothing served in its place"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_companys_brand_reaches_the_pages_only_as_a_colour_token_text_links_and_its_png() {
    let storage = live_storage().await;
    let acme = TenantId::parse("acme").expect("a tenant id");
    storage.tenants.provision(&acme).await.expect("provisioned");
    let at = Timestamp::from_unix_secs(1_800_000_000);
    storage
        .brands
        .set(
            &acme,
            &Brand {
                name: BrandName::parse("Acme <b>Bank</b>").expect("a name"),
                accent: Accent::parse("#1f4fd8").expect("an accent"),
                support: Some(BrandLink::parse("https://help.acme.example/").expect("a link")),
                privacy: None,
                updated_at: at,
            },
        )
        .await
        .expect("a brand");
    let png = logo();
    storage
        .brands
        .set_logo(&acme, &png, at)
        .await
        .expect("a logo");

    let (_, headers, css) = fetch_from(&storage, "/acme/assets/brand.css").await;
    assert_brand_headers(&headers, "text/css; charset=utf-8", "brand.css");
    assert_eq!(
        String::from_utf8(css).expect("text"),
        ":root {\n  --brand-accent: #1f4fd8;\n  --brand-wash: #1f4fd81f;\n}\n"
    );
    let (_, _, json) = fetch_from(&storage, "/acme/assets/brand.json").await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&json).expect("json"),
        serde_json::json!({
            "name": "Acme <b>Bank</b>",
            "support": "https://help.acme.example/",
            "privacy": null,
            "logo": 1_800_000_000_u64,
        }),
        "the name is data for textContent, never markup"
    );
    let (status, headers, served) = fetch_from(&storage, "/acme/assets/logo.png").await;
    assert_eq!(status, StatusCode::OK);
    assert_brand_headers(&headers, "image/png", "logo.png");
    assert_eq!(served, png.as_bytes());
}
