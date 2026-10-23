//! A company's signing keys in its console, by an operator holding `keys`: read with the state the rotation rule gives
//! each, a successor made early only while none waits, and a compromised key withdrawn at once, never leaving the
//! company without a key to sign with, never naming another company's key, and never showing a private half.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tessari_oauth_api::admin_router;
use tessari_oauth_constants::JWKS_MAX_AGE_SECS;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::Timestamp;
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const KEYS: &str = "/admin/acme/api/keys";
const ROTATE: &str = "/admin/acme/api/keys/rotate";

fn change(path: &str, key: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::COOKIE, "__Host-tessari-admin=console-k")
        .header(header::ORIGIN, CONSOLE)
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(body.to_owned()))
        .expect("a request")
}

fn read() -> Request<Body> {
    Request::get(KEYS)
        .header(header::COOKIE, "__Host-tessari-admin=console-k")
        .body(Body::empty())
        .expect("a request")
}

fn withdraw(kid: &str) -> String {
    format!("/admin/acme/api/keys/{kid}/withdraw")
}

async fn send(state: tessari_oauth_api::AdminState, request: Request<Body>) -> Answer {
    answer(
        admin_router(state)
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await
}

/// The `state` the read gives `kid`.
fn state_of(read: &Answer, kid: &str) -> String {
    read.body["keys"]
        .as_array()
        .expect("a key list")
        .iter()
        .find(|key| key["kid"] == kid)
        .unwrap_or_else(|| panic!("{kid} is listed"))["state"]
        .as_str()
        .expect("a state")
        .to_owned()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_makes_one_successor_early_and_withdraws_a_key_at_once() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-k",
        &[OperatorRole::Keys],
        "issuer-k",
        "console-k",
    )
    .await;
    let acme = tenant("acme");
    let first = server.storage.keys.live(&acme).await.expect("read")[0]
        .kid
        .as_str()
        .to_owned();
    let listed = send(state.clone(), read()).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    assert_eq!(listed.body["keys"].as_array().map(Vec::len), Some(1));
    assert_eq!(state_of(&listed, &first), "signing");
    assert_eq!(listed.body["keys"][0]["algorithm"], "ES256");
    let text = listed.body.to_string();
    assert!(
        !text.contains("sealed") && !text.contains("\"d\""),
        "no private half: {text}"
    );

    let made = send(
        state.clone(),
        change(
            ROTATE,
            "rotate-keys-0001",
            r#"{"reason":"scheduled early"}"#,
        ),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    let successor = made.body["kid"].as_str().expect("a kid").to_owned();
    assert_ne!(successor, first);
    assert_eq!(
        made.body["signs_from"],
        NOW + JWKS_MAX_AGE_SECS,
        "it signs once verifiers can have fetched it"
    );
    let again = send(
        state.clone(),
        change(
            ROTATE,
            "rotate-keys-0001",
            r#"{"reason":"scheduled early"}"#,
        ),
    )
    .await;
    assert_eq!(again.body, made.body, "answered as the first was");
    let listed = send(state.clone(), read()).await;
    assert_eq!(state_of(&listed, &first), "signing");
    assert_eq!(state_of(&listed, &successor), "waiting");
    let second = send(
        state.clone(),
        change(ROTATE, "rotate-keys-0002", r#"{"reason":"once more"}"#),
    )
    .await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert_eq!(second.body["code"], "successor_waiting");

    let unknown = send(
        state.clone(),
        change(
            &withdraw("not-a-key"),
            "withdraw-keys-0001",
            r#"{"reason":"leaked"}"#,
        ),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.body["code"], "key_not_found");
    let foreign = server
        .storage
        .keys
        .live(&tenant("initech"))
        .await
        .expect("read")[0]
        .kid
        .as_str()
        .to_owned();
    let crossing = send(
        state.clone(),
        change(
            &withdraw(&foreign),
            "withdraw-keys-0002",
            r#"{"reason":"leaked"}"#,
        ),
    )
    .await;
    assert_eq!(
        crossing.status,
        StatusCode::NOT_FOUND,
        "another company's key"
    );
    assert!(
        !server
            .storage
            .keys
            .live(&tenant("initech"))
            .await
            .expect("read")[0]
            .compromised,
        "left as it was"
    );

    let withdrawn = send(
        state.clone(),
        change(
            &withdraw(&first),
            "withdraw-keys-0003",
            r#"{"reason":"leaked in a support ticket"}"#,
        ),
    )
    .await;
    assert_eq!(withdrawn.status, StatusCode::OK, "{:?}", withdrawn.body);
    assert_eq!(withdrawn.body["withdrawn"], first.as_str());
    assert!(
        withdrawn.body["replacement"].is_null(),
        "a successor already existed"
    );
    let listed = send(state.clone(), read()).await;
    assert_eq!(state_of(&listed, &first), "withdrawn");
    assert_eq!(state_of(&listed, &successor), "signing");
    let signer = server
        .storage
        .keys
        .signer(&acme, &server.kek, Timestamp::from_unix_secs(NOW))
        .await
        .expect("a signer");
    assert_eq!(
        signer.kid().as_str(),
        successor,
        "the withdrawn key signs no more"
    );
    let twice = send(
        state.clone(),
        change(
            &withdraw(&first),
            "withdraw-keys-0004",
            r#"{"reason":"leaked"}"#,
        ),
    )
    .await;
    assert_eq!(twice.status, StatusCode::CONFLICT);
    assert_eq!(twice.body["code"], "already_withdrawn");

    let trail = server
        .storage
        .audit
        .read_after(&acme, 0, 100)
        .await
        .expect("the trail");
    let recorded = |action: &str, reason: &str| {
        trail.iter().any(|record| {
            record.event.kind == AuditKind::AdminAction
                && record.event.action.as_deref() == Some(action)
                && record.event.reason.as_deref() == Some(reason)
                && record.event.actor.as_deref() == Some("operator-k")
        })
    };
    assert!(recorded("keys.rotate", "scheduled early"));
    assert!(recorded("keys.withdraw", "leaked in a support ticket"));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn withdrawing_the_only_key_makes_its_replacement_first() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-k",
        &[OperatorRole::Keys],
        "issuer-k",
        "console-k",
    )
    .await;
    let acme = tenant("acme");
    let only = server.storage.keys.live(&acme).await.expect("read")[0]
        .kid
        .as_str()
        .to_owned();
    let withdrawn = send(
        state.clone(),
        change(
            &withdraw(&only),
            "withdraw-only-0001",
            r#"{"reason":"custody breach"}"#,
        ),
    )
    .await;
    assert_eq!(withdrawn.status, StatusCode::OK, "{:?}", withdrawn.body);
    let replacement = withdrawn.body["replacement"]
        .as_str()
        .expect("a replacement")
        .to_owned();
    let listed = send(state.clone(), read()).await;
    assert_eq!(state_of(&listed, &only), "withdrawn");
    assert_eq!(state_of(&listed, &replacement), "signing");
    let signer = server
        .storage
        .keys
        .signer(&acme, &server.kek, Timestamp::from_unix_secs(NOW))
        .await
        .expect("never without a signer");
    assert_eq!(signer.kid().as_str(), replacement);
}
