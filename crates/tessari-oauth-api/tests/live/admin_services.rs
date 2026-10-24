//! Service credentials on the admin API: an operator in the console registers a program with an Ed25519 key and the
//! `users` role; the program then manages the company's accounts by signing one assertion per request, and every
//! assertion that is not exactly right, and every action reserved to a person in the console, is refused.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ring::signature::Ed25519KeyPair;
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_core::subject::SubjectSector;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{Sector, Timestamp, UserId, base64url};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const AUDIENCE: &str = "https://admin.example.com/admin/acme";
/// RFC 8037 §A.1: the Ed25519 private key `d` and its public `x`.
const SEED: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
const OTHER_SEED: [u8; 32] = [7; 32];
const HEADER: &str = r#"{"alg":"EdDSA","typ":"tessari-admin+jwt"}"#;

fn signed_with(seed: &[u8], header: &str, claims: &str) -> String {
    let pair = Ed25519KeyPair::from_seed_unchecked(seed).expect("a seed is a key");
    let input = format!(
        "{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(claims.as_bytes())
    );
    format!(
        "{input}.{}",
        base64url::encode(pair.sign(input.as_bytes()).as_ref())
    )
}

fn claims(service: &str, aud: &str, exp: u64, jti: &str) -> String {
    format!(r#"{{"iss":"{service}","sub":"{service}","aud":"{aud}","exp":{exp},"jti":"{jti}"}}"#)
}

/// A good assertion of `service` under the RFC key, with its own `jti`.
fn assertion(service: &str, jti: &str) -> String {
    let seed = base64url::decode(SEED).expect("RFC seed");
    signed_with(&seed, HEADER, &claims(service, AUDIENCE, NOW + 30, jti))
}

fn as_service(
    method: &str,
    path: &str,
    compact: &str,
    body: Option<(&str, &str)>,
) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("TessariService {compact}"));
    match body {
        Some((key, json)) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", key)
            .body(Body::from(json.to_owned())),
        None => builder.body(Body::empty()),
    }
    .expect("a request")
}

fn in_console(path: &str, secret: &str, key: &str, json: &str) -> Request<Body> {
    Request::post(path)
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, CONSOLE)
        .header("idempotency-key", key)
        .body(Body::from(json.to_owned()))
        .expect("a request")
}

async fn send(state: &AdminState, request: Request<Body>) -> Answer {
    answer(
        admin_router(state.clone())
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await
}

/// An operator holding `users` in the console, with the service `backend` registered by them.
async fn registered() -> (crate::token_fixture::Server, AdminState) {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-s",
        &[OperatorRole::Users],
        "issuer-s",
        "console-s",
    )
    .await;
    let body = format!(
        r#"{{"service_id":"backend","jwk":{JWK},"roles":["users"],"reason":"the cloud backend"}}"#
    );
    let made = send(
        &state,
        in_console(
            "/admin/acme/api/services",
            "console-s",
            "register-backend-1",
            &body,
        ),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.body);
    assert_eq!(made.body["roles"], serde_json::json!(["users"]));
    (server, state)
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_registered_service_manages_accounts_by_its_assertions() {
    let (server, state) = registered().await;
    let opened = send(
        &state,
        as_service(
            "POST",
            "/admin/acme/api/users",
            &assertion("backend", "open-1"),
            Some((
                "open-customer-001",
                r#"{"email":"customer@example.com","reason":"cloud sign-up"}"#,
            )),
        ),
    )
    .await;
    assert_eq!(opened.status, StatusCode::CREATED, "{:?}", opened.body);
    let user = opened.body["user"]
        .as_str()
        .expect("the account's id")
        .to_owned();

    let listed = send(
        &state,
        as_service(
            "GET",
            "/admin/acme/api/users",
            &assertion("backend", "list-1"),
            None,
        ),
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);

    let subject = server
        .storage
        .subjects
        .pairwise(
            &tenant("acme"),
            &server.kek,
            &SubjectSector::Named(Sector::parse("tessaridb-cloud").expect("a sector")),
            &UserId::parse(user.clone()).expect("a user id"),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("a subject");
    let path = format!("/admin/acme/api/users/by-subject?sector=tessaridb-cloud&sub={subject}");
    let found = send(
        &state,
        as_service("GET", &path, &assertion("backend", "find-1"), None),
    )
    .await;
    assert_eq!(found.status, StatusCode::OK, "{:?}", found.body);
    assert_eq!(found.body["user"], user.as_str());
    assert_ne!(
        found.body["email"], "customer@example.com",
        "the address stays masked"
    );
    let elsewhere = format!("/admin/acme/api/users/by-subject?sector=other-product&sub={subject}");
    let missing = send(
        &state,
        as_service("GET", &elsewhere, &assertion("backend", "find-2"), None),
    )
    .await;
    assert_eq!(
        missing.status,
        StatusCode::NOT_FOUND,
        "another sector's subject names nobody"
    );

    let disabled = send(
        &state,
        as_service(
            "POST",
            &format!("/admin/acme/api/users/{user}/disable"),
            &assertion("backend", "block-1"),
            Some(("block-customer-01", r#"{"reason":"unpaid, ticket 3"}"#)),
        ),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{:?}", disabled.body);
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 200)
        .await
        .expect("the trail");
    assert!(
        trail
            .iter()
            .map(|record| &record.event)
            .any(|event| event.kind == AuditKind::AdminAction
                && event.actor.as_deref() == Some("service:backend")
                && event.reason.as_deref() == Some("unpaid, ticket 3")),
        "the change is recorded as the service's, with its reason"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_assertion_that_is_not_exactly_right_is_refused() {
    let (_server, state) = registered().await;
    let seed = base64url::decode(SEED).expect("RFC seed");
    let spent = assertion("backend", "once-1");
    let first = send(
        &state,
        as_service("GET", "/admin/acme/api/users", &spent, None),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    let cases = [
        ("replayed", spent),
        (
            "another company",
            signed_with(
                &seed,
                HEADER,
                &claims(
                    "backend",
                    "https://admin.example.com/admin/initech",
                    NOW + 30,
                    "x-1",
                ),
            ),
        ),
        (
            "the issuer as audience",
            signed_with(
                &seed,
                HEADER,
                &claims("backend", "https://id.example.com/acme", NOW + 30, "x-2"),
            ),
        ),
        (
            "expired",
            signed_with(&seed, HEADER, &claims("backend", AUDIENCE, NOW - 20, "x-3")),
        ),
        (
            "too long",
            signed_with(
                &seed,
                HEADER,
                &claims("backend", AUDIENCE, NOW + 600, "x-4"),
            ),
        ),
        (
            "client type",
            signed_with(
                &seed,
                r#"{"alg":"EdDSA","typ":"client-authentication+jwt"}"#,
                &claims("backend", AUDIENCE, NOW + 30, "x-5"),
            ),
        ),
        ("unknown service", assertion("reports", "x-6")),
        (
            "another key",
            signed_with(
                &OTHER_SEED,
                HEADER,
                &claims("backend", AUDIENCE, NOW + 30, "x-7"),
            ),
        ),
        ("not a jws", "not-a-jws".to_owned()),
    ];
    for (case, compact) in cases {
        let refused = send(
            &state,
            as_service("GET", "/admin/acme/api/users", &compact, None),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::UNAUTHORIZED,
            "{case}: {:?}",
            refused.body
        );
        assert_eq!(refused.body["code"], "service_refused", "{case}");
    }
    let foreign = send(
        &state,
        as_service(
            "GET",
            "/admin/initech/api/users",
            &assertion("backend", "x-8"),
            None,
        ),
    )
    .await;
    assert_eq!(
        foreign.status,
        StatusCode::UNAUTHORIZED,
        "a service is the company's own: {:?}",
        foreign.body
    );
    let removed = send(
        &state,
        in_console(
            "/admin/acme/api/services/backend/remove",
            "console-s",
            "remove-backend-1",
            r#"{"reason":"rotated"}"#,
        ),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);
    let after = send(
        &state,
        as_service(
            "GET",
            "/admin/acme/api/users",
            &assertion("backend", "x-9"),
            None,
        ),
    )
    .await;
    assert_eq!(
        after.status,
        StatusCode::UNAUTHORIZED,
        "a removed service is refused"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_service_cannot_act_beyond_its_role_or_as_a_person() {
    let (_server, state) = registered().await;
    let clients = send(
        &state,
        as_service(
            "GET",
            "/admin/acme/api/clients",
            &assertion("backend", "r-1"),
            None,
        ),
    )
    .await;
    assert_eq!(clients.status, StatusCode::FORBIDDEN, "{:?}", clients.body);
    assert_eq!(clients.body["code"], "role_required");
    let body = format!(
        r#"{{"service_id":"second","jwk":{JWK},"roles":["users"],"reason":"mint another"}}"#
    );
    let console_only = [
        (
            "POST",
            "/admin/acme/api/services",
            Some(("mint-service-0001", body.as_str())),
        ),
        (
            "POST",
            "/admin/acme/api/operators/operator-s/grants/users",
            Some(("grant-users-00001", r#"{"reason":"raise"}"#)),
        ),
        ("GET", "/admin/acme/api/services", None),
        ("GET", "/admin/acme/api/me", None),
    ];
    for (number, (method, path, sent)) in console_only.into_iter().enumerate() {
        let jti = format!("c-{number}");
        let refused = send(
            &state,
            as_service(method, path, &assertion("backend", &jti), sent),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "{path}: {:?}",
            refused.body
        );
        assert_eq!(refused.body["code"], "console_only", "{path}");
    }
    let opened = send(
        &state,
        as_service(
            "POST",
            "/admin/acme/api/users",
            &assertion("backend", "o-1"),
            Some((
                "open-someone-0001",
                r#"{"email":"someone@example.com","reason":"sign-up"}"#,
            )),
        ),
    )
    .await;
    let user = opened.body["user"].as_str().expect("an account").to_owned();
    // Even with the console's own origin, a signed header never stands for a person.
    let reveal = Request::post(format!("/admin/acme/api/users/{user}/email/reveal"))
        .header(
            header::AUTHORIZATION,
            format!("TessariService {}", assertion("backend", "v-1")),
        )
        .header(header::ORIGIN, CONSOLE)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"reason":"curious"}"#))
        .expect("a request");
    let revealed = send(&state, reveal).await;
    assert_eq!(
        revealed.status,
        StatusCode::FORBIDDEN,
        "{:?}",
        revealed.body
    );
    assert_eq!(revealed.body["code"], "console_only");
    let bare = Request::get("/admin/acme/api/users")
        .body(Body::empty())
        .expect("a request");
    assert_eq!(
        send(&state, bare).await.status,
        StatusCode::UNAUTHORIZED,
        "no cookie and no assertion"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_registration_outside_the_rules_is_refused() {
    let (_server, state) = registered().await;
    let p256 = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
    let cases = [
        format!(r#"{{"service_id":"wide","jwk":{JWK},"roles":["clients"],"reason":"r"}}"#),
        format!(r#"{{"service_id":"none","jwk":{JWK},"roles":[],"reason":"r"}}"#),
        format!(r#"{{"service_id":"ec","jwk":{p256},"roles":["users"],"reason":"r"}}"#),
        format!(r#"{{"service_id":"Bad Name","jwk":{JWK},"roles":["users"],"reason":"r"}}"#),
        format!(
            r#"{{"service_id":"extra","jwk":{JWK},"roles":["users"],"reason":"r","tenant":"initech"}}"#
        ),
    ];
    for (number, case) in cases.iter().enumerate() {
        let key = format!("refused-service-{number:02}");
        let refused = send(
            &state,
            in_console("/admin/acme/api/services", "console-s", &key, case),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "case {number}: {:?}",
            refused.body
        );
    }
    let body =
        format!(r#"{{"service_id":"backend","jwk":{JWK},"roles":["users"],"reason":"again"}}"#);
    let taken = send(
        &state,
        in_console(
            "/admin/acme/api/services",
            "console-s",
            "register-again-01",
            &body,
        ),
    )
    .await;
    assert_eq!(taken.status, StatusCode::CONFLICT, "{:?}", taken.body);
    assert_eq!(taken.body["code"], "service_taken");
    let listed = send(
        &state,
        Request::get("/admin/acme/api/services")
            .header(header::COOKIE, "__Host-tessari-admin=console-s")
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    assert_eq!(listed.body["services"].as_array().map(Vec::len), Some(1));
}
