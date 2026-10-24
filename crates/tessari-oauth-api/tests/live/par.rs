//! The pushed authorization request endpoint (RFC 9126): a client that authenticates as it does at `/token` pushes the
//! parameters it would have put in the browser's URL and receives a `request_uri` naming them for a minute; a request
//! the authorization endpoint would refuse is refused here, to the client, with the `error` code alone.

use axum::http::StatusCode;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{ClientId, Timestamp};

use crate::routes::{Answer, answer};
use crate::token_fixture::{
    BROWSER_COOKIE, NOW, REDIRECT, Server, browser, plenty, server, state, tenant, uncached,
};
use axum::body::Body;
use axum::http::Request;
use tessari_oauth_api::public_router;
use tower::ServiceExt;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// POST `pairs` as a form to `acme`'s pushed authorization request endpoint.
async fn push(server: &Server, pairs: &[(&str, &str)]) -> Answer {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let response = public_router(state(server, plenty()))
        .oneshot(
            Request::post("/acme/oauth2/par")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("a request"),
        )
        .await
        .expect("the router answers");
    answer(response).await
}

/// What `portal`, a public client, would send to the authorization endpoint.
fn valid() -> Vec<(&'static str, &'static str)> {
    vec![
        ("response_type", "code"),
        ("client_id", "portal"),
        ("redirect_uri", REDIRECT),
        ("scope", "api:read"),
        ("state", "af0ifjsldkj"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]
}

fn with(name: &'static str, value: &'static str) -> Vec<(&'static str, &'static str)> {
    let mut pairs: Vec<_> = valid()
        .into_iter()
        .filter(|(key, _)| *key != name)
        .collect();
    pairs.push((name, value));
    pairs
}

fn refused(answer: &Answer, status: StatusCode, error: &str, case: &str) {
    assert_eq!(answer.status, status, "{case}: {}", answer.body);
    assert_eq!(
        answer.body,
        serde_json::json!({ "error": error }),
        "{case}: the code alone"
    );
    uncached(answer);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_pushed_request_is_named_by_a_request_uri_its_client_alone_can_claim() {
    let server = server(2).await;
    let answered = push(&server, &with("nonce", "n-0S6_WzA2Mj")).await;
    assert_eq!(answered.status, StatusCode::CREATED, "{}", answered.body);
    uncached(&answered);
    assert_eq!(answered.body["expires_in"], 60);
    let request_uri = answered.body["request_uri"]
        .as_str()
        .expect("a request_uri");
    let id = request_uri
        .strip_prefix(PREFIX)
        .unwrap_or_else(|| panic!("a request_uri in the RFC 9126 namespace: {request_uri}"));
    let claimed = server
        .storage
        .interactions
        .claim(
            &tenant("acme"),
            id,
            &ClientId::parse("portal").expect("a client id"),
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .expect("the pushed request is there to claim");
    assert_eq!(claimed.redirect_uri, REDIRECT);
    assert_eq!(claimed.state.as_deref(), Some("af0ifjsldkj"));
    assert_eq!(claimed.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    assert_eq!(claimed.challenge.as_str(), CHALLENGE);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_the_authorization_endpoint_would_refuse_is_refused_to_the_client() {
    let server = server(2).await;
    refused(
        &push(&server, &with("client_id", "nobody")).await,
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        "a client that does not authenticate",
    );
    for (pairs, error, case) in [
        (
            with("redirect_uri", "https://attacker.example.net/catch"),
            "invalid_request",
            "an unregistered redirect URI",
        ),
        (
            with("response_type", "token"),
            "unsupported_response_type",
            "an implicit request",
        ),
        (
            with("scope", "api:admin"),
            "invalid_scope",
            "a scope beyond the ceiling",
        ),
        (
            with("request_uri", "urn:ietf:params:oauth:request_uri:x"),
            "invalid_request",
            "a push that names a request_uri itself",
        ),
    ] {
        refused(
            &push(&server, &pairs).await,
            StatusCode::BAD_REQUEST,
            error,
            case,
        );
    }
    let trail: Vec<AuditEvent> = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .map(|record| record.event)
        .collect();
    let reasons: Vec<Option<String>> = trail.iter().map(|event| event.reason.clone()).collect();
    assert_eq!(
        reasons,
        [
            "UnknownClient",
            "UnregisteredRedirectUri",
            "UnsupportedResponseType",
            "ScopeBeyondCeiling",
            "RequestUriInPush",
        ]
        .map(|reason| Some(reason.to_owned())),
        "every refusal recorded with its reason, and nothing for a push"
    );
    assert!(trail.iter().all(|event| event.kind == AuditKind::Refused));
}

/// GET `acme`'s authorization endpoint with `pairs`; the status and the `Location`, when there is one.
async fn authorize(server: &Server, pairs: &[(&str, &str)]) -> (StatusCode, Option<url::Url>) {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let response = public_router(state(server, plenty()))
        .oneshot(
            Request::get(format!("/acme/oauth2/authorize?{query}"))
                .header("cookie", BROWSER_COOKIE)
                .body(Body::empty())
                .expect("a request"),
        )
        .await
        .expect("the router answers");
    let location = response
        .headers()
        .get("location")
        .map(|value| url::Url::parse(value.to_str().expect("ASCII")).expect("a URL"));
    (response.status(), location)
}

/// The `request_uri` a push of `pairs` answered with.
async fn pushed_uri(server: &Server, pairs: &[(&str, &str)]) -> String {
    let answered = push(server, pairs).await;
    assert_eq!(answered.status, StatusCode::CREATED, "{}", answered.body);
    answered.body["request_uri"]
        .as_str()
        .expect("a request_uri")
        .to_owned()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_browser_brings_a_request_uri_once_and_is_handed_to_sign_in_with_it() {
    let server = server(2).await;
    let request_uri = pushed_uri(&server, &valid()).await;
    let id = request_uri.strip_prefix(PREFIX).expect("namespaced");
    // Nothing in the query but the client and the request_uri is read: the pushed request is the request.
    let (status, location) = authorize(
        &server,
        &[
            ("client_id", "portal"),
            ("request_uri", &request_uri),
            ("redirect_uri", "https://attacker.example.net/catch"),
            ("scope", "api:write"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = location.expect("a Location");
    assert_eq!(
        location.as_str(),
        format!("https://id.example.com/acme/login?interaction={id}"),
        "the pushed request's own id carries the sign-in"
    );
    let pending = server
        .storage
        .interactions
        .find(
            &tenant("acme"),
            id,
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .expect("now a pending sign-in");
    assert_eq!(pending.redirect_uri, REDIRECT);
    assert_eq!(pending.scopes.iter().collect::<Vec<_>>(), ["api:read"]);
    let (again, location) = authorize(
        &server,
        &[("client_id", "portal"), ("request_uri", &request_uri)],
    )
    .await;
    assert_eq!((again, location), (StatusCode::BAD_REQUEST, None), "once");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_uri_another_client_or_nobody_pushed_is_refused_at_the_server() {
    let server = server(2).await;
    let request_uri = pushed_uri(&server, &valid()).await;
    for (pairs, case) in [
        (
            vec![
                ("client_id", "kiosk"),
                ("request_uri", request_uri.as_str()),
            ],
            "another client",
        ),
        (vec![("request_uri", request_uri.as_str())], "no client"),
        (
            vec![
                ("client_id", "portal"),
                ("request_uri", "urn:ietf:params:oauth:request_uri:never"),
            ],
            "never pushed",
        ),
    ] {
        assert_eq!(
            authorize(&server, &pairs).await,
            (StatusCode::BAD_REQUEST, None),
            "{case}"
        );
    }
    let (status, _) = authorize(
        &server,
        &[("client_id", "portal"), ("request_uri", &request_uri)],
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "still its own client's to bring"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_pushed_request_asking_for_no_page_is_refused_with_login_required() {
    let server = server(2).await;
    let mut silent = valid();
    silent.push(("prompt", "none"));
    let request_uri = pushed_uri(&server, &silent).await;
    let (status, location) = authorize(
        &server,
        &[("client_id", "portal"), ("request_uri", &request_uri)],
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let found: Vec<(String, String)> = location
        .expect("a Location")
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(
        found,
        [
            ("error", "login_required"),
            ("state", "af0ifjsldkj"),
            ("iss", "https://id.example.com/acme"),
        ]
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
    );
}
