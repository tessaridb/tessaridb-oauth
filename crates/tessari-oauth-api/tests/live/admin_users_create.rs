//! An operator holding `users` opens an account in their own company for an address, once however often the request
//! is sent; an address already taken is refused, the answer names the address only masked, and the opening is recorded
//! with why. Nobody without `users`, and no request from another origin, opens one.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::UserStatus;
use tessari_oauth_types::{EmailAddress, UserId};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const PATH: &str = "/admin/acme/api/users";

fn opening(secret: &str, origin: Option<&str>, key: &str, body: &str) -> Request<Body> {
    let mut request = Request::post(PATH)
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key);
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    request
        .body(Body::from(body.to_owned()))
        .expect("a request")
}

async fn send(state: AdminState, request: Request<Body>) -> Answer {
    answer(
        admin_router(state)
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await
}

const NEW_HIRE: &str = r#"{"email":"lee@acme.example","reason":"new hire, ticket 52"}"#;

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_opens_an_account_once_and_a_taken_address_is_refused() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;
    let opened = send(
        state.clone(),
        opening("console-u", Some(CONSOLE), "open-lee-0000001", NEW_HIRE),
    )
    .await;
    assert_eq!(opened.status, StatusCode::CREATED, "{:?}", opened.body);
    assert_eq!(opened.body["email"], "l***@acme.example");
    assert_eq!(opened.body["status"], "active");
    assert!(!opened.body.to_string().contains("lee@"));
    let user = UserId::parse(opened.body["user"].as_str().expect("an id")).expect("a user id");
    let account = server
        .storage
        .users
        .find(&tenant("acme"), &user)
        .await
        .expect("an answer")
        .expect("the account");
    assert_eq!(account.status, UserStatus::Active);
    assert_eq!(
        account.email,
        EmailAddress::parse("lee@acme.example").expect("an address")
    );
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 500)
        .await
        .expect("the trail reads");
    assert!(trail.iter().any(|message| {
        message.event.kind == AuditKind::AdminAction
            && message.event.action.as_deref() == Some("users.create")
            && message.event.user.as_ref() == Some(&user)
            && message.event.reason.as_deref() == Some("new hire, ticket 52")
    }));

    let repeated = send(
        state.clone(),
        opening("console-u", Some(CONSOLE), "open-lee-0000001", NEW_HIRE),
    )
    .await;
    assert_eq!(repeated.status, StatusCode::CREATED);
    assert_eq!(repeated.body, opened.body);
    let taken = send(
        state.clone(),
        opening("console-u", Some(CONSOLE), "open-lee-0000002", NEW_HIRE),
    )
    .await;
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(taken.body["code"], "email_taken");
    let not_an_address = send(
        state,
        opening(
            "console-u",
            Some(CONSOLE),
            "open-lee-0000003",
            r#"{"email":"lee","reason":"new hire"}"#,
        ),
    )
    .await;
    assert_eq!(not_an_address.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn nobody_without_users_and_nothing_from_another_origin_opens_an_account() {
    let server = server(2).await;
    let auditor = signed_in_as(
        &server,
        "operator-a",
        &[OperatorRole::Audit],
        "issuer-a",
        "console-a",
    )
    .await;
    let refused = send(
        auditor,
        opening("console-a", Some(CONSOLE), "open-lee-0000004", NEW_HIRE),
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body["code"], "role_required");
    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;
    let elsewhere = send(
        state,
        opening(
            "console-u",
            Some("https://evil.example.com"),
            "open-lee-0000005",
            NEW_HIRE,
        ),
    )
    .await;
    assert_eq!(elsewhere.status, StatusCode::FORBIDDEN);
    assert_eq!(elsewhere.body["code"], "cross_origin");
    let address = EmailAddress::parse("lee@acme.example").expect("an address");
    let found = server
        .storage
        .users
        .find_by_email(&tenant("acme"), &address)
        .await
        .expect("an answer");
    assert!(
        found.is_none(),
        "an account was opened by a refused request"
    );
}
