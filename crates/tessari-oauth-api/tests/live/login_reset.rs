//! Password reset over a live store: a request answers alike for every address and queues one mail each, only a known
//! address's carrying a link; the link sets a new password once, keeps the second factor, ends the sessions and tells
//! the address; a refused password leaves the link usable; without a relay the request is refused alike.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_infrastructure::custody::Verdict;
use tessari_oauth_storage::outbox::QueuedMail;
use tessari_oauth_types::{SessionSecret, Timestamp, UserId};
use tower::ServiceExt as _;

use crate::account_password::session;
use crate::login::{KNOWN, post};
use crate::login_password::{RIGHT, identified, with_password};
use crate::routes::answer;
use crate::token_fixture::{NOW, Server, passwords, plenty, server, state, tenant};

const NEW: &str = "a long enough new password for ada";
const LINK: &str = "https://id.example.com/acme/login/reset#token=";

/// Every mail queued in `acme`, opened, oldest claim order.
async fn queued(server: &Server) -> Vec<QueuedMail> {
    server
        .storage
        .outbox
        .claim(&tenant("acme"), &server.kek, 50)
        .await
        .expect("claimed")
}

/// The token in the link of the one mail `mails` holds for `address`.
fn token_for(mails: &[QueuedMail], address: &str) -> String {
    let mail = mails
        .iter()
        .find(|mail| mail.to.as_ref().map(|to| to.as_str()) == Some(address))
        .expect("a mail to the address");
    let (_, after) = mail.text.split_once(LINK).expect("a link");
    after
        .split_whitespace()
        .next()
        .expect("a token")
        .to_owned()
}

/// Whether `password` is the stored password of `user`.
async fn holds(server: &Server, user: &UserId, password: &str) -> bool {
    let stored = server
        .storage
        .users
        .password(&tenant("acme"), user)
        .await
        .expect("an answer");
    let Some(stored) = stored else { return false };
    matches!(
        passwords()
            .verify(password, Some(&stored.hash))
            .await
            .expect("verified"),
        Verdict::Match { .. }
    )
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_answers_alike_and_queues_one_mail_each_only_a_known_address_with_a_link() {
    let server = server(2).await;
    with_password(&server, KNOWN).await;

    let answers = [
        post(&server, "reset", None, json!({ "email": KNOWN })).await,
        post(
            &server,
            "reset",
            None,
            json!({ "email": "nobody@example.com" }),
        )
        .await,
        post(&server, "reset", None, json!({ "email": "not an address" })).await,
    ];

    for answered in &answers {
        assert_eq!(answered.status, StatusCode::ACCEPTED);
        assert_eq!(answered.body, answers[0].body);
    }
    let mails = queued(&server).await;
    assert_eq!(mails.len(), 3, "{mails:?}");
    let addressed: Vec<&QueuedMail> = mails.iter().filter(|mail| mail.to.is_some()).collect();
    assert_eq!(addressed.len(), 1, "{mails:?}");
    assert!(addressed[0].text.contains(LINK));
    assert_eq!(token_for(&mails, KNOWN).len(), 43, "256 bits, base64url");
    for mail in &mails {
        assert_eq!(
            mail.subject, addressed[0].subject,
            "one subject for every request"
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_link_sets_the_password_once_keeps_the_second_factor_and_ends_the_sessions() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    server
        .storage
        .factors
        .enroll_totp(
            &tenant("acme"),
            &server.kek,
            &user,
            &[9; 20],
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("enrolled");
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;
    post(&server, "reset", None, json!({ "email": KNOWN })).await;
    let token = token_for(&queued(&server).await, KNOWN);

    let completed = post(
        &server,
        "reset/complete",
        None,
        json!({ "token": token, "password": NEW }),
    )
    .await;

    assert_eq!(
        completed.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        completed.body
    );
    assert!(holds(&server, &user, NEW).await);
    assert!(!holds(&server, &user, RIGHT).await);
    assert!(
        server
            .storage
            .factors
            .summary(&tenant("acme"), &user)
            .await
            .expect("a summary")
            .totp,
        "the second factor stays"
    );
    assert_eq!(
        server
            .storage
            .sessions
            .find(
                &tenant("acme"),
                &SessionSecret::from_secret(cookie),
                Timestamp::from_unix_secs(NOW)
            )
            .await
            .expect("an answer"),
        None,
        "every session ended"
    );
    let notices = queued(&server).await;
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert_eq!(notices[0].to.as_ref().map(|to| to.as_str()), Some(KNOWN));
    assert!(!notices[0].text.contains(LINK), "a notice carries no link");
    let again = post(
        &server,
        "reset/complete",
        None,
        json!({ "token": token, "password": "another long enough password" }),
    )
    .await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(again.body["code"], "code_rejected");
    assert!(holds(&server, &user, NEW).await);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_refused_password_leaves_the_link_usable_and_an_unknown_token_resets_nobody() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    post(&server, "reset", None, json!({ "email": KNOWN })).await;
    let token = token_for(&queued(&server).await, KNOWN);

    let short = post(
        &server,
        "reset/complete",
        None,
        json!({ "token": token, "password": "short" }),
    )
    .await;
    let unknown = post(
        &server,
        "reset/complete",
        None,
        json!({ "token": "never-issued", "password": NEW }),
    )
    .await;
    let completed = post(
        &server,
        "reset/complete",
        None,
        json!({ "token": token, "password": NEW }),
    )
    .await;

    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    assert_eq!(short.body["code"], "password_rejected");
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown.body["code"], "code_rejected");
    assert_eq!(completed.status, StatusCode::NO_CONTENT);
    assert!(holds(&server, &user, NEW).await);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_a_relay_a_request_is_refused_alike_and_queues_nothing() {
    let server = server(2).await;
    with_password(&server, KNOWN).await;
    let mut public = state(&server, plenty());
    public.mail = false;

    for email in [KNOWN, "nobody@example.com"] {
        let request = Request::post("/acme/login/api/reset")
            .header("content-type", "application/json")
            .extension(ConnectInfo(std::net::SocketAddr::from((
                [192, 0, 2, 1],
                443,
            ))))
            .body(Body::from(json!({ "email": email }).to_string()))
            .expect("a request");
        let answered = answer(
            public_router(public.clone())
                .oneshot(request)
                .await
                .expect("the router answers"),
        )
        .await;
        assert_eq!(answered.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answered.body["code"], "mail_unavailable");
    }
    assert!(queued(&server).await.is_empty());
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn signing_in_stops_an_outstanding_link_working() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    post(&server, "reset", None, json!({ "email": KNOWN })).await;
    let token = token_for(&queued(&server).await, KNOWN);
    let cookie = identified(&server, KNOWN).await;
    let signed_in = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{:?}", signed_in.body);

    let completed = post(
        &server,
        "reset/complete",
        None,
        json!({ "token": token, "password": NEW }),
    )
    .await;

    assert_eq!(completed.status, StatusCode::BAD_REQUEST);
    assert_eq!(completed.body["code"], "code_rejected");
    assert!(holds(&server, &user, RIGHT).await);
}
