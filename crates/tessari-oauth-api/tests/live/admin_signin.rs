//! Signing in to the admin console begins at the console and leaves for the company's issuer: one request to its
//! authorization endpoint as `admin-console`, redirected back only to the console's callback, asking for `openid`
//! with a PKCE S256 challenge, a `state` and a `nonce`, while the browser takes a sign-in cookie whose sign-in the
//! console keeps until it comes back. The cookie is `__Host-` and `Secure` over https, plain on a loopback console.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::companies::Served;
use tessari_oauth_types::{Challenge, SigninBinding, Timestamp};
use tower::ServiceExt;
use url::Url;

use crate::token_fixture::{NOW, Server, server, tenant};

fn console_state(server: &Server, console: &str) -> AdminState {
    let served = Served::new("https://id.example.com");
    served.replace([tenant("acme")]);
    AdminState {
        admin: Arc::clone(&server.storage.admin),
        served: Arc::new(served),
        console: Arc::from(console),
        clock: Arc::new(|| Timestamp::from_unix_secs(NOW)),
    }
}

async fn get(state: AdminState, path: &str) -> axum::response::Response {
    admin_router(state)
        .oneshot(Request::get(path).body(Body::empty()).expect("a request"))
        .await
        .expect("an answer")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_signin_leaves_for_the_company_issuer_and_is_kept_for_its_browser() {
    let server = server(2).await;
    let answer = get(
        console_state(&server, "https://admin.example.com"),
        "/admin/acme/signin",
    )
    .await;
    assert_eq!(answer.status(), StatusCode::SEE_OTHER);
    let location = Url::parse(
        answer.headers()[header::LOCATION]
            .to_str()
            .expect("a location"),
    )
    .expect("a URL");
    assert_eq!(
        location.as_str().split('?').next(),
        Some("https://id.example.com/acme/oauth2/authorize")
    );
    let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", "admin-console"),
        (
            "redirect_uri",
            "https://admin.example.com/admin/acme/callback",
        ),
        ("scope", "openid"),
        ("code_challenge_method", "S256"),
    ] {
        assert_eq!(query.get(name).map(String::as_str), Some(value), "{name}");
    }
    let cookie = answer.headers()[header::SET_COOKIE]
        .to_str()
        .expect("a cookie");
    let (pair, attributes) = cookie.split_once(';').expect("attributes");
    let value = pair
        .strip_prefix("__Host-tessari-admin-signin=")
        .expect("the console's sign-in cookie");
    for attribute in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=600",
    ] {
        assert!(attributes.contains(attribute), "{attribute} in {cookie}");
    }
    let pending = server
        .storage
        .admin
        .take(&tenant("acme"), &SigninBinding::from_secret(value))
        .await
        .expect("an answer")
        .expect("the sign-in is kept for this browser");
    assert!(pending.state_matches(&query["state"]));
    assert_eq!(pending.nonce, query["nonce"]);
    assert_eq!(
        Challenge::of(&pending.verifier)
            .expect("a verifier")
            .as_str(),
        query["code_challenge"]
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_loopback_console_in_the_clear_sets_a_plain_cookie_and_an_unknown_company_finds_nothing()
{
    let server = server(2).await;
    let state = console_state(&server, "http://127.0.0.1:9443");
    let answer = get(state.clone(), "/admin/acme/signin").await;
    assert_eq!(answer.status(), StatusCode::SEE_OTHER);
    let cookie = answer.headers()[header::SET_COOKIE]
        .to_str()
        .expect("a cookie");
    assert!(cookie.starts_with("tessari-admin-signin="), "{cookie}");
    assert!(!cookie.contains("Secure"), "{cookie}");
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    let unknown = get(state, "/admin/globex/signin").await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert!(unknown.headers().get(header::SET_COOKIE).is_none());
}
