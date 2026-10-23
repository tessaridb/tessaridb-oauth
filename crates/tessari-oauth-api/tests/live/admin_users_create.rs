//! An operator holding `users` opens an account in their own company for an address, once however often the request
//! is sent; an address already taken is refused, the answer names the address only masked, and the opening is recorded
//! with why. Nobody without `users`, and no request from another origin, opens one.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::{Registered, StoredPassword, UserStatus};
use tessari_oauth_types::{EmailAddress, EnrolmentCode, Timestamp, UserId};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, server, tenant};

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

/// An enrolment code for `user` asked by the console session `secret` under the `Idempotency-Key` `key`.
fn enrolment(user: &str, secret: &str, key: &str) -> Request<Body> {
    Request::post(format!("/admin/acme/api/users/{user}/enrolment"))
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::ORIGIN, CONSOLE)
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(r#"{"reason":"first sign-in, ticket 53"}"#))
        .expect("a request")
}

async fn opened(server: &crate::token_fixture::Server, email: &str) -> UserId {
    let address = EmailAddress::parse(email).expect("an address");
    match server
        .storage
        .users
        .register(&tenant("acme"), &address, Timestamp::from_unix_secs(NOW))
        .await
        .expect("registered")
    {
        Registered::Created(user) => user,
        Registered::AddressTaken => panic!("{email} is taken"),
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_enrolment_code_is_shown_once_and_kept_nowhere_but_as_its_digest() {
    let server = server(2).await;
    let kim = opened(&server, "kim@acme.example").await;
    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;
    let issued = send(
        state.clone(),
        enrolment(kim.as_str(), "console-u", "enrol-kim-000001"),
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{:?}", issued.body);
    assert_eq!(issued.body["user"], kim.as_str());
    assert_eq!(issued.body["valid_secs"], 259_200);
    let code = issued.body["code"].as_str().expect("a code").to_owned();
    assert!(code.len() >= 40, "{code}");
    let named = server
        .storage
        .enrolments
        .find(&tenant("acme"), &EnrolmentCode::from_secret(code.clone()))
        .await
        .expect("an answer");
    assert_eq!(named.as_ref(), Some(&kim));

    let repeated = send(
        state.clone(),
        enrolment(kim.as_str(), "console-u", "enrol-kim-000001"),
    )
    .await;
    assert_eq!(repeated.status, StatusCode::CREATED);
    assert!(repeated.body["code"].is_null(), "{:?}", repeated.body);
    assert_eq!(repeated.body["shown_once"], true);
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 500)
        .await
        .expect("the trail reads");
    assert!(trail.iter().any(|message| {
        message.event.kind == AuditKind::AdminAction
            && message.event.action.as_deref() == Some("users.enrol")
            && message.event.user.as_ref() == Some(&kim)
    }));
    assert!(
        trail
            .iter()
            .all(|message| !format!("{:?}", message.event).contains(&code)),
        "the code reached the trail"
    );

    let replaced = send(
        state.clone(),
        enrolment(kim.as_str(), "console-u", "enrol-kim-000002"),
    )
    .await;
    assert_eq!(replaced.status, StatusCode::CREATED);
    let old = server
        .storage
        .enrolments
        .find(&tenant("acme"), &EnrolmentCode::from_secret(code))
        .await
        .expect("an answer");
    assert!(old.is_none(), "a replaced code still enrols");

    server
        .storage
        .users
        .set_password(
            &tenant("acme"),
            &kim,
            &StoredPassword {
                hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g".to_owned(),
                pepper: 1,
            },
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("a password");
    let enrolled = send(
        state.clone(),
        enrolment(kim.as_str(), "console-u", "enrol-kim-000003"),
    )
    .await;
    assert_eq!(enrolled.status, StatusCode::CONFLICT);
    assert_eq!(enrolled.body["code"], "already_enrolled");

    let bo = opened(&server, "bo@acme.example").await;
    let moved = server
        .storage
        .users
        .set_status(
            &tenant("acme"),
            &bo,
            UserStatus::Active,
            UserStatus::Disabled,
        )
        .await
        .expect("an answer");
    assert!(moved);
    let disabled = send(
        state.clone(),
        enrolment(bo.as_str(), "console-u", "enrol-bo-0000001"),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::CONFLICT);
    assert_eq!(disabled.body["code"], "account_disabled");
    let nobody = send(
        state,
        enrolment("user-nobody", "console-u", "enrol-nobody-001"),
    )
    .await;
    assert_eq!(nobody.status, StatusCode::NOT_FOUND);
    assert_eq!(nobody.body["code"], "user_not_found");

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
        enrolment(bo.as_str(), "console-a", "enrol-bo-0000002"),
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body["code"], "role_required");
}

/// An enrolment code for `user` sent by mail, asked by the console session `secret` under the key `key`.
fn mailed_enrolment(user: &str, secret: &str, key: &str) -> Request<Body> {
    Request::post(format!("/admin/acme/api/users/{user}/enrolment"))
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::ORIGIN, CONSOLE)
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(
            r#"{"reason":"first sign-in, ticket 54","by_mail":true}"#,
        ))
        .expect("a request")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_enrolment_code_sent_by_mail_is_never_shown_and_its_link_enrols() {
    let server = server(2).await;
    let kim = opened(&server, "kim@acme.example").await;
    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;
    let unset = send(
        AdminState {
            mail: false,
            ..state.clone()
        },
        mailed_enrolment(kim.as_str(), "console-u", "enrol-mail-000001"),
    )
    .await;
    assert_eq!(
        unset.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{:?}",
        unset.body
    );
    assert_eq!(unset.body["code"], "mail_unavailable");

    let mailed = send(
        state.clone(),
        mailed_enrolment(kim.as_str(), "console-u", "enrol-mail-000002"),
    )
    .await;
    assert_eq!(mailed.status, StatusCode::CREATED, "{:?}", mailed.body);
    assert!(mailed.body["code"].is_null(), "{:?}", mailed.body);
    assert_eq!(mailed.body["mailed"], true);
    let mails = server
        .storage
        .outbox
        .claim(&tenant("acme"), &server.kek, 50)
        .await
        .expect("claimed");
    assert_eq!(mails.len(), 1, "one mail, and none for the refused request");
    let mail = &mails[0];
    assert_eq!(
        mail.to.as_ref().map(|to| to.as_str()),
        Some("kim@acme.example")
    );
    let (_, after) = mail
        .text
        .split_once("https://id.example.com/acme/login/enrol#code=")
        .expect("the enrolment link");
    let code = after.split_whitespace().next().expect("a code").to_owned();
    let named = server
        .storage
        .enrolments
        .find(&tenant("acme"), &EnrolmentCode::from_secret(code))
        .await
        .expect("an answer");
    assert_eq!(
        named.as_ref(),
        Some(&kim),
        "the mailed code enrols the account"
    );
}
