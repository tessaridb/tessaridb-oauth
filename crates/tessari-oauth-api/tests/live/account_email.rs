//! Changing the sign-in address over a live store: a recent sign-in asks, both addresses get mail, the new one confirms
//! once, the old one cancels once, an address another account holds answers alike and gets no link, and a stale
//! sign-in, an unreadable address or the account's own address change nothing.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_constants::{EMAIL_CHANGE_HOLD_SECS, EMAIL_CHANGE_REQUEST_LIMIT};
use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::outbox::QueuedMail;

use crate::account_grants::call;
use crate::account_password::session;
use crate::login::{KNOWN, post, register};
use crate::login_password::with_password;
use crate::token_fixture::{NOW, Server, server, tenant};

const NEW: &str = "ada@new.example";

async fn queued(server: &Server) -> Vec<QueuedMail> {
    server
        .storage
        .outbox
        .claim(&tenant("acme"), &server.kek, 50)
        .await
        .expect("claimed")
}

/// The mail queued to `to`, of the two an address change sends.
fn to<'a>(mails: &'a [QueuedMail], to: &str) -> &'a QueuedMail {
    mails
        .iter()
        .find(|mail| mail.to.as_ref().map(|address| address.as_str()) == Some(to))
        .unwrap_or_else(|| panic!("a mail to {to} in {mails:?}"))
}

/// The token after `marker` in `mail`'s link.
fn token_after(mail: &QueuedMail, marker: &str) -> String {
    let (_, after) = mail.text.split_once(marker).expect("a link");
    after.split_whitespace().next().expect("a token").to_owned()
}

async fn ask(server: &Server, cookie: Option<&str>, email: &str) -> crate::routes::Answer {
    call(
        server,
        "POST",
        "me/email",
        cookie,
        Some(json!({ "email": email })),
    )
    .await
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_recent_sign_in_asks_and_each_address_gets_its_own_link() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;

    let asked = ask(&server, Some(&cookie), NEW).await;
    assert_eq!(asked.status, StatusCode::ACCEPTED, "{:?}", asked.body);
    let mails = queued(&server).await;
    assert_eq!(mails.len(), 2, "{mails:?}");
    let confirm = token_after(to(&mails, NEW), "/login/email#confirm=");
    let old = to(&mails, KNOWN);
    assert!(
        old.text.contains(NEW),
        "the old address is told where the account is going"
    );
    let cancel = token_after(old, "/login/email#cancel=");
    assert_eq!((confirm.len(), cancel.len()), (43, 43));

    let confirmed = post(&server, "email/confirm", None, json!({ "token": confirm })).await;
    assert_eq!(
        confirmed.status,
        StatusCode::ACCEPTED,
        "{:?}",
        confirmed.body
    );
    assert_eq!(confirmed.body["effective_at"], NOW + EMAIL_CHANGE_HOLD_SECS);
    for (path, token) in [("email/confirm", &confirm), ("email/cancel", &confirm)] {
        let refused = post(&server, path, None, json!({ "token": token })).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(refused.body["code"], "code_rejected", "{path}");
    }

    let cancelled = post(&server, "email/cancel", None, json!({ "token": cancel })).await;
    assert_eq!(
        cancelled.status,
        StatusCode::NO_CONTENT,
        "{:?}",
        cancelled.body
    );
    let again = post(&server, "email/cancel", None, json!({ "token": cancel })).await;
    assert_eq!(again.body["code"], "code_rejected");
    let account = server
        .storage
        .users
        .find(&tenant("acme"), &user)
        .await
        .expect("an answer")
        .expect("the account");
    assert_eq!(account.email.as_str(), KNOWN, "nothing changed yet");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_address_another_account_holds_answers_alike_and_gets_no_link() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    register(&server, "bob@example.com").await;
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;

    let asked = ask(&server, Some(&cookie), "bob@example.com").await;

    assert_eq!(asked.status, StatusCode::ACCEPTED, "{:?}", asked.body);
    let mails = queued(&server).await;
    assert_eq!(mails.len(), 2, "the same work as a free address: {mails:?}");
    let held = to(&mails, "bob@example.com");
    assert!(
        !held.text.contains("#confirm="),
        "nothing the holder could confirm"
    );
    assert!(to(&mails, KNOWN).text.contains("#cancel="));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_stale_sign_in_a_bad_address_or_the_same_address_change_nothing() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    let stale = session(&server, &user, "session-old", &[Method::Password], 3_600).await;
    let fresh = session(&server, &user, "session-new", &[Method::Password], 0).await;

    let old = ask(&server, Some(&stale), NEW).await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);
    assert_eq!(old.body["code"], "reauthentication_required");
    let nobody = ask(&server, None, NEW).await;
    assert_eq!(nobody.body["code"], "session_required");
    let unreadable = ask(&server, Some(&fresh), "not an address").await;
    assert_eq!(unreadable.status, StatusCode::BAD_REQUEST);
    assert_eq!(unreadable.body["code"], "email_rejected");
    let same = ask(&server, Some(&fresh), KNOWN).await;
    assert_eq!(same.status, StatusCode::NO_CONTENT);
    assert!(queued(&server).await.is_empty());
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_account_asks_for_few_changes_an_hour_so_it_cannot_mail_at_will() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;

    for at in 0..EMAIL_CHANGE_REQUEST_LIMIT {
        let asked = ask(&server, Some(&cookie), &format!("ada{at}@new.example")).await;
        assert_eq!(asked.status, StatusCode::ACCEPTED, "request {at}");
    }
    let mailed = queued(&server).await.len();
    let past = ask(&server, Some(&cookie), "ada-last@new.example").await;

    assert_eq!(past.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(past.body["code"], "rate_limited");
    assert_eq!(queued(&server).await.len(), 0, "nothing more is mailed");
    assert_eq!(
        u64::try_from(mailed).expect("a count"),
        EMAIL_CHANGE_REQUEST_LIMIT * 2
    );
}
