//! Notices: a change to how an account signs in queues one mail to the account's address saying what changed, with no
//! link; signing out everywhere is told too; without a relay nothing is queued and the change still happens.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::outbox::QueuedMail;

use crate::account_grants::call;
use crate::account_password::session;
use crate::login::KNOWN;
use crate::login_password::with_password;
use crate::token_fixture::{Server, server, tenant};

const NEW: &str = "a much longer phrase than before";

async fn queued(server: &Server) -> Vec<QueuedMail> {
    server
        .storage
        .outbox
        .claim(&tenant("acme"), &server.kek, 50)
        .await
        .expect("claimed")
}

fn told(mails: &[QueuedMail], what: &str) {
    assert_eq!(mails.len(), 1, "{mails:?}");
    assert_eq!(mails[0].to.as_ref().map(|to| to.as_str()), Some(KNOWN));
    assert_eq!(mails[0].subject, "Your sign-in changed");
    assert!(mails[0].text.contains(what), "{}", mails[0].text);
    assert!(!mails[0].text.contains("#token="), "no link");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_password_change_tells_the_address() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;

    let changed = call(
        &server,
        "POST",
        "password",
        Some(&cookie),
        Some(json!({ "password": NEW })),
    )
    .await;

    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    told(&queued(&server).await, "Its password was changed.");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn signing_out_everywhere_tells_the_address() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    let cookie = session(&server, &user, "session-1", &[Method::Password], 0).await;

    let ended = call(
        &server,
        "POST",
        "sessions/end-all",
        Some(&cookie),
        Some(json!({})),
    )
    .await;

    assert_eq!(ended.status, StatusCode::OK, "{}", ended.body);
    told(&queued(&server).await, "Every session was signed out.");
}
