//! The pushed authorization request endpoint (RFC 9126): a client that authenticates as it does at `/token` pushes the
//! parameters it would have put in the browser's URL and receives a `request_uri` naming them for a minute; a request
//! the authorization endpoint would refuse is refused here, to the client, with the `error` code alone.

use axum::http::StatusCode;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{ClientId, Timestamp};

use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, REDIRECT, Server, plenty, server, state, tenant, uncached};
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
