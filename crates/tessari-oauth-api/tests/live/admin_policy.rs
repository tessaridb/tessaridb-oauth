//! The first console change: a company's two-factor policy, read and changed by an operator holding `policy`. A change
//! names the policy it replaces, carries its reason and an `Idempotency-Key`, comes from the console's own origin, is
//! made once however often it is sent, and is recorded with who made it and why. Nobody else gets as far as the policy.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::admin_router;
use tessari_oauth_core::two_factor::TwoFactorPolicy;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const PATH: &str = "/admin/acme/api/policy/two-factor";

/// A request from the console with the session cookie `secret`, the `Idempotency-Key` `key` and the JSON `body`.
fn change(path: &str, secret: &str, key: Option<&str>, body: &str) -> Request<Body> {
    let mut request = Request::put(path)
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::ORIGIN, CONSOLE)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        request = request.header("idempotency-key", key);
    }
    request
        .body(Body::from(body.to_owned()))
        .expect("a request")
}

fn read(path: &str, secret: &str) -> Request<Body> {
    Request::get(path)
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .body(Body::empty())
        .expect("a request")
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

const TO_REQUIRED: &str =
    r#"{"expected":"optional","policy":"required","reason":"audit finding 12"}"#;

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_changes_the_policy_once_however_often_the_change_is_sent() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-p",
        &[OperatorRole::Policy],
        "issuer-p",
        "console-p",
    )
    .await;
    let first = send(state.clone(), read(PATH, "console-p")).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["policy"], "optional");
    let key = "change-policy-0001";
    let made = send(
        state.clone(),
        change(PATH, "console-p", Some(key), TO_REQUIRED),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    assert_eq!(made.body["policy"], "required");
    let again = send(
        state.clone(),
        change(PATH, "console-p", Some(key), TO_REQUIRED),
    )
    .await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.body, made.body, "answered as the first was");
    assert_eq!(
        server.storage.policies.two_factor(&tenant("acme")).await,
        Ok(TwoFactorPolicy::Required)
    );
    let stale = send(
        state.clone(),
        change(
            PATH,
            "console-p",
            Some("change-policy-0002"),
            r#"{"expected":"optional","policy":"off","reason":"rollout"}"#,
        ),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(stale.body["code"], "changed_meanwhile");
    assert_eq!(
        server.storage.policies.two_factor(&tenant("acme")).await,
        Ok(TwoFactorPolicy::Required),
        "a change from a stale view changes nothing"
    );
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail");
    let changes: Vec<_> = trail
        .iter()
        .filter(|record| record.event.kind == AuditKind::AdminAction)
        .map(|record| &record.event)
        .collect();
    assert_eq!(
        changes.len(),
        2,
        "the change and the refused change, each once"
    );
    assert_eq!(changes[0].actor.as_deref(), Some("operator-p"));
    assert_eq!(changes[0].role, Some(OperatorRole::Policy));
    assert_eq!(changes[0].action.as_deref(), Some("policy.two_factor"));
    assert_eq!(changes[0].reason.as_deref(), Some("audit finding 12"));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn nobody_else_reaches_the_policy() {
    let server = server(2).await;
    let policy = signed_in_as(
        &server,
        "operator-p",
        &[OperatorRole::Policy],
        "issuer-p",
        "console-p",
    )
    .await;
    let support = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;
    let cases: Vec<(&str, Request<Body>, StatusCode, &str)> = vec![
        (
            "no role, read",
            read(PATH, "console-u"),
            StatusCode::FORBIDDEN,
            "role_required",
        ),
        (
            "no role, change",
            change(PATH, "console-u", Some("change-policy-0100"), TO_REQUIRED),
            StatusCode::FORBIDDEN,
            "role_required",
        ),
        (
            "another company",
            read("/admin/initech/api/policy/two-factor", "console-p"),
            StatusCode::UNAUTHORIZED,
            "session_required",
        ),
        (
            "no reason",
            change(
                PATH,
                "console-p",
                Some("change-policy-0101"),
                r#"{"expected":"optional","policy":"required","reason":"  "}"#,
            ),
            StatusCode::BAD_REQUEST,
            "reason_required",
        ),
        (
            "no key",
            change(PATH, "console-p", None, TO_REQUIRED),
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
        ),
        (
            "a field nobody offered",
            change(
                PATH,
                "console-p",
                Some("change-policy-0102"),
                r#"{"expected":"optional","policy":"required","reason":"x","tenant":"initech"}"#,
            ),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
    ];
    for (name, request, status, code) in cases {
        let state = if name.starts_with("no role") {
            support.clone()
        } else {
            policy.clone()
        };
        let refused = send(state, request).await;
        assert_eq!(refused.status, status, "{name}: {:?}", refused.body);
        assert_eq!(refused.body["code"], code, "{name}");
    }
    let mut foreign = change(PATH, "console-p", Some("change-policy-0103"), TO_REQUIRED);
    foreign.headers_mut().insert(
        header::ORIGIN,
        "https://evil.example.com".parse().expect("a header"),
    );
    let cross = send(policy.clone(), foreign).await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
    assert_eq!(cross.body["code"], "cross_origin");
    let made = send(
        policy.clone(),
        change(PATH, "console-p", Some("change-policy-0104"), TO_REQUIRED),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK);
    let reused = send(
        policy,
        change(
            PATH,
            "console-p",
            Some("change-policy-0104"),
            r#"{"expected":"required","policy":"off","reason":"another change"}"#,
        ),
    )
    .await;
    assert_eq!(reused.status, StatusCode::CONFLICT);
    assert_eq!(reused.body["code"], "idempotency_key_reused");
    assert_eq!(
        server.storage.policies.two_factor(&tenant("acme")).await,
        Ok(TwoFactorPolicy::Required),
        "only the one allowed change was made"
    );
    let role_refusals = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .filter(|record| {
            record.event.kind == AuditKind::Refused
                && record.event.reason.as_deref() == Some("role_required")
        })
        .count();
    assert_eq!(role_refusals, 2, "each missing role is audited");
}

const REGISTRATION: &str = "/admin/acme/api/policy/registration";

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn registration_opens_from_the_revision_read_and_refuses_what_is_not_a_domain() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-r",
        &[OperatorRole::Policy],
        "issuer-r",
        "console-r",
    )
    .await;
    let first = send(state.clone(), read(REGISTRATION, "console-r")).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(
        first.body,
        serde_json::json!({"open": false, "domains": [], "revision": 0}),
        "closed until a company opens it"
    );
    let open = r#"{"revision":0,"open":true,"domains":["Example.com"],"reason":"pilot"}"#;
    let made = send(
        state.clone(),
        change(REGISTRATION, "console-r", Some("registration-0001"), open),
    )
    .await;
    assert_eq!(made.status, StatusCode::OK, "{:?}", made.body);
    assert_eq!(
        made.body,
        serde_json::json!({"open": true, "domains": ["example.com"], "revision": 1})
    );
    let stale = r#"{"revision":0,"open":false,"domains":[],"reason":"close it"}"#;
    let moved = send(
        state.clone(),
        change(REGISTRATION, "console-r", Some("registration-0002"), stale),
    )
    .await;
    assert_eq!(moved.status, StatusCode::CONFLICT);
    assert_eq!(moved.body["code"], "changed_meanwhile");
    let wildcard = r#"{"revision":1,"open":true,"domains":["*.example.com"],"reason":"wider"}"#;
    let refused = send(
        state.clone(),
        change(
            REGISTRATION,
            "console-r",
            Some("registration-0003"),
            wildcard,
        ),
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["code"], "domains_rejected");
    let kept = send(state, read(REGISTRATION, "console-r")).await;
    assert_eq!(
        kept.body,
        serde_json::json!({"open": true, "domains": ["example.com"], "revision": 1}),
        "neither refusal changed it"
    );
}
