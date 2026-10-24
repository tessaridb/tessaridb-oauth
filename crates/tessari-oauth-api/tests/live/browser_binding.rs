//! A pending authorization belongs to the browser that brought it: `/authorize` keeps a browser's own cookie, and the
//! sign-in, the consent step and the code are answered only to the browser holding it. Another browser that has the
//! request's id, even with a session of its own, gets nothing, and the request still waits for its own browser.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_types::{Challenge, ClientId, Resource, ScopeSet, Timestamp};
use tower::ServiceExt;

use crate::authorize_resume::signed_in;
use crate::routes::{Answer, header};
use crate::token_fixture::{API, NOW, REDIRECT, Server, browser, plenty, server, state, tenant};

const OTHER: &str = "__Host-tessari-browser=browser-b";
const SESSION_COOKIE: &str = "__Host-tessari-session";

/// Send `method` to `path` carrying `cookie` and, when given, a JSON `body`.
async fn call(
    server: &Server,
    method: &str,
    path: &str,
    cookie: &str,
    body: Option<serde_json::Value>,
) -> Answer {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 50_000))));
    let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
    let response = public_router(state(server, plenty()))
        .oneshot(request.body(body).expect("a request"))
        .await
        .expect("the router answers");
    let (status, headers) = (response.status(), response.headers().clone());
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    // A refusal shown at the server is a page, not JSON; its status and headers are the answer.
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Answer {
        status,
        headers,
        body,
    }
}

/// A pending authorization for `portal`, brought by the test browser.
async fn pending(server: &Server) -> String {
    let request = AuthorizationRequest {
        client_id: ClientId::parse("portal").expect("a client id"),
        redirect_uri: REDIRECT.to_owned(),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        challenge: Challenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .expect("a challenge"),
        state: None,
        resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
        nonce: None,
        dpop_jkt: None,
        silent: false,
        max_age: None,
    };
    server
        .storage
        .interactions
        .open(
            &tenant("acme"),
            &request,
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("kept")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_browser_that_brings_its_cookie_keeps_it() {
    let server = server(2).await;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", "portal"),
            ("redirect_uri", REDIRECT),
            ("scope", "api:read"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("code_challenge_method", "S256"),
            ("resource", API),
        ])
        .finish();
    let answered = call(
        &server,
        "GET",
        &format!("/acme/oauth2/authorize?{query}"),
        "theme=dark; __Host-tessari-browser=browser-a",
        None,
    )
    .await;
    assert_eq!(answered.status, StatusCode::SEE_OTHER, "{}", answered.body);
    assert!(
        header(&answered, "set-cookie").starts_with("__Host-tessari-browser=browser-a;"),
        "the browser keeps its own value"
    );
    let location = url::Url::parse(header(&answered, "location")).expect("a URL");
    let (_, id) = location
        .query_pairs()
        .find(|(name, _)| name == "interaction")
        .expect("the interaction id");
    let kept = server
        .storage
        .interactions
        .find(
            &tenant("acme"),
            &id,
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers");
    assert!(kept.is_some(), "kept for the browser that brought it");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn another_browser_cannot_sign_in_consent_or_take_the_code() {
    let server = server(2).await;
    let (_, session, _) = signed_in(&server, "curie@example.com").await;
    let interaction = pending(&server).await;
    let elsewhere = format!("{OTHER}; {SESSION_COOKIE}={session}");
    let resume = format!("/acme/oauth2/authorize/resume?interaction={interaction}");
    for cookie in [elsewhere.as_str(), &format!("{SESSION_COOKIE}={session}")] {
        let answered = call(&server, "GET", &resume, cookie, None).await;
        assert_eq!(answered.status, StatusCode::BAD_REQUEST, "resume: {cookie}");
        assert!(
            answered.headers.get("location").is_none(),
            "never redirected"
        );
    }
    let consent = format!("/acme/login/api/consent?interaction={interaction}");
    let asked = call(&server, "GET", &consent, &elsewhere, None).await;
    assert_eq!(asked.status, StatusCode::GONE, "consent page");
    assert_eq!(asked.body["code"], "signin_expired");
    let decision = json!({ "interaction": interaction, "decision": "deny" });
    let decided = call(
        &server,
        "POST",
        "/acme/login/api/consent",
        &elsewhere,
        Some(decision),
    )
    .await;
    assert_eq!(decided.status, StatusCode::GONE, "consent decision");
    let begun = call(
        &server,
        "POST",
        "/acme/login/api/begin",
        OTHER,
        Some(json!({ "interaction": interaction })),
    )
    .await;
    assert_eq!(begun.status, StatusCode::GONE, "sign-in");
    assert!(
        begun.headers.get("set-cookie").is_none(),
        "no sign-in begun"
    );
    let own = format!("__Host-tessari-browser=browser-a; {SESSION_COOKIE}={session}");
    let answered = call(&server, "GET", &resume, &own, None).await;
    assert_eq!(
        answered.status,
        StatusCode::SEE_OTHER,
        "its own browser goes on"
    );
    assert!(
        header(&answered, "location").contains("/consent?interaction="),
        "to be asked, the request still pending"
    );
}
