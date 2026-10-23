//! Address verification over a live store: a signed-in user asks for a link, the link verifies the account's address
//! once, a verified address gets no more mail, enrolment sends one link, and without a relay a request is refused.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::outbox::QueuedMail;
use tessari_oauth_types::{EnrolmentCode, Timestamp, UserId};
use tower::ServiceExt as _;

use crate::account_grants::call;
use crate::account_password::session;
use crate::login::{KNOWN, post, register};
use crate::login_password::with_password;
use crate::routes::answer;
use crate::token_fixture::{BROWSER_COOKIE, NOW, Server, plenty, server, state, tenant};

const LINK: &str = "https://id.example.com/acme/login/verify#token=";

/// Every mail queued in `acme`, opened.
async fn queued(server: &Server) -> Vec<QueuedMail> {
    server
        .storage
        .outbox
        .claim(&tenant("acme"), &server.kek, 50)
        .await
        .expect("claimed")
}

/// The token in the link of the one mail `mails` holds.
fn token_in(mails: &[QueuedMail]) -> String {
    assert_eq!(mails.len(), 1, "{mails:?}");
    let (_, after) = mails[0].text.split_once(LINK).expect("a link");
    after.split_whitespace().next().expect("a token").to_owned()
}

async fn verified(server: &Server, user: &UserId) -> bool {
    server
        .storage
        .users
        .find(&tenant("acme"), user)
        .await
        .expect("an answer")
        .expect("the account")
        .email_verified
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_link_asked_for_by_the_signed_in_user_verifies_the_address_once() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;

    let asked = call(&server, "POST", "me/verify", Some(&cookie), Some(json!({}))).await;
    assert_eq!(asked.status, StatusCode::ACCEPTED, "{:?}", asked.body);
    let mails = queued(&server).await;
    let token = token_in(&mails);
    assert_eq!(mails[0].to.as_ref().map(|to| to.as_str()), Some(KNOWN));
    assert_eq!(token.len(), 43, "256 bits, base64url");
    assert!(!verified(&server, &user).await, "asking proves nothing yet");

    let opened = post(&server, "verify", None, json!({ "token": token })).await;
    assert_eq!(opened.status, StatusCode::NO_CONTENT, "{:?}", opened.body);
    assert!(verified(&server, &user).await);

    for again in [token.as_str(), "never-issued"] {
        let refused = post(&server, "verify", None, json!({ "token": again })).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(refused.body["code"], "code_rejected");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_verified_address_gets_no_mail_and_a_stranger_gets_no_link() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    let address = tessari_oauth_types::EmailAddress::parse(KNOWN).expect("an address");
    assert_eq!(
        server
            .storage
            .users
            .mark_verified(
                &tenant("acme"),
                &user,
                &address,
                Timestamp::from_unix_secs(NOW)
            )
            .await,
        Ok(true)
    );
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;

    let asked = call(&server, "POST", "me/verify", Some(&cookie), Some(json!({}))).await;
    let stranger = call(&server, "POST", "me/verify", None, Some(json!({}))).await;

    assert_eq!(asked.status, StatusCode::NO_CONTENT, "{:?}", asked.body);
    assert_eq!(stranger.status, StatusCode::UNAUTHORIZED);
    assert_eq!(stranger.body["code"], "session_required");
    assert!(queued(&server).await.is_empty());
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn enrolment_sends_one_verification_link() {
    let server = server(2).await;
    let user = register(&server, KNOWN).await;
    server
        .storage
        .enrolments
        .issue(
            &tenant("acme"),
            &EnrolmentCode::from_secret("code-1"),
            &user,
            "operator-1",
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("issued");

    let enrolled = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": "a long enough first password for ada" }),
    )
    .await;

    assert_eq!(
        enrolled.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        enrolled.body
    );
    let token = token_in(&queued(&server).await);
    let opened = post(&server, "verify", None, json!({ "token": token })).await;
    assert_eq!(opened.status, StatusCode::NO_CONTENT);
    assert!(verified(&server, &user).await);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_a_relay_a_request_is_refused_and_queues_nothing() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;
    let mut public = state(&server, plenty());
    public.mail = false;

    let request = Request::post("/acme/account/api/me/verify")
        .header("content-type", "application/json")
        .header(
            "cookie",
            format!("{BROWSER_COOKIE}; __Host-tessari-session={cookie}"),
        )
        .extension(ConnectInfo(std::net::SocketAddr::from((
            [192, 0, 2, 9],
            50_000,
        ))))
        .body(Body::from("{}"))
        .expect("a request");
    let answered = answer(
        public_router(public)
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await;

    assert_eq!(answered.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answered.body["code"], "mail_unavailable");
    assert!(queued(&server).await.is_empty());
}
