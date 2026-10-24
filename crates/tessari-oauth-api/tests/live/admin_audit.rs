//! An operator holding `audit` reads their company's trail in order, a page at a time behind its positions, each
//! message carrying only the fields it was written with and none outside the trail's own set. Another company's trail
//! is not theirs, and nobody without `audit` reads it.

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{Timestamp, UserId};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, Server, server, tenant};

/// Every field a trail message may carry in the console's answer.
const FIELDS: [&str; 16] = [
    "position",
    "at",
    "kind",
    "client_id",
    "user",
    "subject",
    "scopes",
    "audience",
    "jti",
    "auth_method",
    "bound_to",
    "reason",
    "families",
    "actor",
    "role",
    "action",
];

async fn read(state: AdminState, path: &str, secret: &str) -> Answer {
    answer(
        admin_router(state)
            .oneshot(
                Request::get(path)
                    .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("an answer"),
    )
    .await
}

async fn written(server: &Server, company: &str, event: &AuditEvent) {
    server
        .storage
        .audit
        .record(&tenant(company), event, Timestamp::from_unix_secs(NOW))
        .await
        .expect("recorded");
}

fn events(page: &Answer) -> &Vec<Value> {
    page.body["events"].as_array().expect("a list")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_company_trail_is_read_in_order_with_only_the_fields_each_message_carries() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-a",
        &[OperatorRole::Audit],
        "issuer-a",
        "console-a",
    )
    .await;
    written(
        &server,
        "acme",
        &AuditEvent {
            user: Some(UserId::parse("user-7").expect("a user id")),
            reason: Some("user_disabled".to_owned()),
            families: Some(3),
            ..AuditEvent::of(AuditKind::Cascade)
        },
    )
    .await;
    written(
        &server,
        "initech",
        &AuditEvent {
            reason: Some("initech-only".to_owned()),
            ..AuditEvent::of(AuditKind::Refused)
        },
    )
    .await;

    let first = read(state.clone(), "/admin/acme/api/audit?limit=1", "console-a").await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    assert_eq!(events(&first).len(), 1);
    assert_eq!(events(&first)[0]["position"], 1);
    assert_eq!(first.body["next"], 1);
    let rest = read(state.clone(), "/admin/acme/api/audit?after=1", "console-a").await;
    assert_eq!(rest.status, StatusCode::OK, "{:?}", rest.body);
    assert!(rest.body["next"].is_null());
    let all: Vec<&Value> = events(&first).iter().chain(events(&rest)).collect();
    let positions: Vec<u64> = all
        .iter()
        .map(|event| event["position"].as_u64().expect("a position"))
        .collect();
    let dense: Vec<u64> = (1..=u64::try_from(positions.len()).expect("a count")).collect();
    assert_eq!(positions, dense);
    let allowed: BTreeSet<&str> = FIELDS.into_iter().collect();
    for event in &all {
        let keys = event.as_object().expect("an object");
        assert!(
            keys.keys().all(|key| allowed.contains(key.as_str())),
            "{event}"
        );
        assert!(keys.values().all(|value| !value.is_null()), "{event}");
    }
    let cascade = all
        .iter()
        .find(|event| event["kind"] == "cascade")
        .expect("the cascade");
    assert_eq!(cascade["user"], "user-7");
    assert_eq!(cascade["families"], 3);
    assert_eq!(cascade["at"], NOW);
    assert!(cascade.get("jti").is_none());
    assert!(
        all.iter().all(|event| event["reason"] != "initech-only"),
        "another company's trail"
    );
    assert!(
        all.iter()
            .any(|event| event["kind"] == "operator_granted" && event["role"] == "audit")
    );

    for limit in ["0", "101", "all"] {
        let refused = read(
            state.clone(),
            &format!("/admin/acme/api/audit?limit={limit}"),
            "console-a",
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "limit {limit}");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn nobody_without_audit_reads_the_trail() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;
    let refused = read(state, "/admin/acme/api/audit", "console-u").await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body["code"], "role_required");
    assert!(refused.body.get("events").is_none());
}
