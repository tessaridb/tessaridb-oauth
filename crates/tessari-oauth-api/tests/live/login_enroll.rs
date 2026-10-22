//! Enrolment over a live store: a code an operator issued lets its user set a first password once; an unknown or
//! spent code is refused alike; a refused password leaves the code usable; an account with a password keeps it.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_infrastructure::custody::Verdict;
use tessari_oauth_types::{EnrolmentCode, Timestamp, UserId};

use crate::login::{KNOWN, post, register};
use crate::login_password::{RIGHT, with_password};
use crate::token_fixture::{NOW, Server, passwords, server, tenant};

const NEW: &str = "a long enough first password for ada";

async fn issued(server: &Server, user: &UserId, code: &str) {
    server
        .storage
        .enrolments
        .issue(
            &tenant("acme"),
            &EnrolmentCode::from_secret(code),
            user,
            "operator-1",
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("issued");
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
async fn a_code_sets_the_first_password_once() {
    let server = server(2).await;
    let user = register(&server, KNOWN).await;
    issued(&server, &user, "code-1").await;
    let enrolled = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": NEW }),
    )
    .await;
    assert_eq!(enrolled.status, StatusCode::NO_CONTENT);
    assert!(holds(&server, &user, NEW).await);
    let again = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": NEW }),
    )
    .await;
    let unknown = post(
        &server,
        "enroll",
        None,
        json!({ "code": "never", "password": NEW }),
    )
    .await;
    for refused in [&again, &unknown] {
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(refused.body["code"], "code_rejected");
    }
    assert_eq!(
        again.body, unknown.body,
        "a spent code and an unknown one read alike"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_refused_password_leaves_the_code_usable() {
    let server = server(2).await;
    let user = register(&server, KNOWN).await;
    issued(&server, &user, "code-1").await;
    let short = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": "short" }),
    )
    .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    assert_eq!(short.body["code"], "password_rejected");
    assert!(!holds(&server, &user, "short").await);
    let enrolled = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": NEW }),
    )
    .await;
    assert_eq!(enrolled.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_account_with_a_password_keeps_it() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    issued(&server, &user, "code-1").await;
    let refused = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": NEW }),
    )
    .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.body["code"], "already_enrolled");
    assert!(holds(&server, &user, RIGHT).await);
    assert!(!holds(&server, &user, NEW).await);
}
