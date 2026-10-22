//! The second-factor steps over a live store: a one-time code signs in once, a recovery code is spent once and
//! recorded, a wrong code is answered alike and counted against the identified address and the client address, a
//! held address is answered before any code is checked, and a code before the password is refused.

use std::net::SocketAddr;

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::signin::SigninKey;
use tessari_oauth_core::totp::code_at;
use tessari_oauth_infrastructure::custody::recovery_digest;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_types::{Timestamp, UserId};

use crate::login::{post, post_from, refused, signin};
use crate::login_password::{RIGHT, SOURCE, account, fail, identified, with_password};
use crate::token_fixture::{NOW, Server, plenty, server, tenant};

pub(crate) const ADA: &str = "ada@example.com";
const SECRET: [u8; 20] = [7; 20];
pub(crate) const RECOVERY: &str = "7K3M-9QXZ-AB12-CD34";

/// `ADA` with a password, a one-time code factor and one recovery code.
pub(crate) async fn enrolled(server: &Server) -> UserId {
    let user = with_password(server, ADA).await;
    let at = Timestamp::from_unix_secs(NOW);
    server
        .storage
        .factors
        .enroll_totp(&tenant("acme"), &server.kek, &user, &SECRET, at)
        .await
        .expect("enrolled");
    let digest = recovery_digest(RECOVERY).expect("a recovery code");
    server
        .storage
        .factors
        .issue_recovery_codes(&tenant("acme"), &user, &[digest], at)
        .await
        .expect("issued");
    user
}

/// A sign-in for `ADA` past the password, by its cookie.
pub(crate) async fn at_second_factor(server: &Server) -> String {
    let cookie = identified(server, ADA).await;
    let answered = post(
        server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    assert_eq!(answered.body, json!({ "next": "second_factor" }));
    cookie
}

/// The code of the step the server's clock stands in.
pub(crate) fn current_code() -> String {
    format!("{:06}", code_at(&SECRET, NOW / 30))
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_one_time_code_signs_in_once() {
    let server = server(2).await;
    enrolled(&server).await;
    let cookie = at_second_factor(&server).await;
    let answered = post(
        &server,
        "totp",
        Some(&cookie),
        json!({ "code": current_code() }),
    )
    .await;
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(answered.body, json!({ "next": "complete" }));
    assert_eq!(
        signin(&server, &cookie).await.ceremony.verified_methods(),
        &[Method::Password, Method::Totp]
    );
    let again = at_second_factor(&server).await;
    let replayed = post(
        &server,
        "totp",
        Some(&again),
        json!({ "code": current_code() }),
    )
    .await;
    refused(
        &replayed,
        StatusCode::UNAUTHORIZED,
        "credentials_rejected",
        "replayed",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_wrong_code_is_counted_against_the_address_and_the_client() {
    let server = server(2).await;
    enrolled(&server).await;
    let wrong_totp = if current_code() == "000000" {
        "111111"
    } else {
        "000000"
    };
    let wrong_recovery = "0000-0000-0000-0000";
    // Each key one short of its hold, the client-address cases each from an address of their own.
    for (step, wrong, key, peer) in [
        ("totp", wrong_totp, SigninKey::Account, SOURCE),
        ("totp", wrong_totp, SigninKey::Source, "198.51.100.1"),
        ("recovery", wrong_recovery, SigninKey::Account, SOURCE),
        (
            "recovery",
            wrong_recovery,
            SigninKey::Source,
            "198.51.100.2",
        ),
    ] {
        let (value, short) = match key {
            SigninKey::Source => (peer.to_owned(), 50),
            _ => (account(ADA), 5),
        };
        // After the password, whose success forgets the address's failures.
        let cookie = at_second_factor(&server).await;
        fail(&server, key, &value, short).await;
        let from: SocketAddr = format!("{peer}:50000").parse().expect("an address");
        let body = json!({ "code": wrong }).to_string();
        let answered = post_from(&server, plenty(), from, step, Some(&cookie), body).await;
        refused(
            &answered,
            StatusCode::UNAUTHORIZED,
            "credentials_rejected",
            step,
        );
        let held = server
            .storage
            .throttle
            .signin_hold(&[(key, &value)], Timestamp::from_unix_secs(NOW))
            .await
            .expect("the store answers");
        assert!(held.is_some(), "{step}: the route counted {key:?}");
        server
            .storage
            .throttle
            .signin_succeeded(&account(ADA))
            .await
            .expect("forgotten");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_held_address_is_answered_before_any_code_is_checked() {
    let server = server(2).await;
    enrolled(&server).await;
    let cookie = at_second_factor(&server).await;
    fail(&server, SigninKey::Account, &account(ADA), 10).await;
    let answered = post(
        &server,
        "totp",
        Some(&cookie),
        json!({ "code": current_code() }),
    )
    .await;
    refused(
        &answered,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "held",
    );
    let recovery = post(
        &server,
        "recovery",
        Some(&cookie),
        json!({ "code": RECOVERY }),
    )
    .await;
    refused(
        &recovery,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "held",
    );
    assert_eq!(
        signin(&server, &cookie).await.ceremony.verified_methods(),
        &[Method::Password],
        "neither code got through a hold"
    );
    server
        .storage
        .throttle
        .signin_succeeded(&account(ADA))
        .await
        .expect("forgotten");
    let later = post(
        &server,
        "totp",
        Some(&cookie),
        json!({ "code": current_code() }),
    )
    .await;
    assert_eq!(later.status, StatusCode::OK, "the held code was not spent");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_recovery_code_is_spent_once_and_recorded() {
    let server = server(2).await;
    let user = enrolled(&server).await;
    let cookie = at_second_factor(&server).await;
    // Typed back off paper: lower case, no hyphens.
    let typed = RECOVERY.replace('-', "").to_lowercase();
    let answered = post(&server, "recovery", Some(&cookie), json!({ "code": typed })).await;
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(answered.body, json!({ "next": "complete" }));
    assert_eq!(
        signin(&server, &cookie).await.ceremony.verified_methods(),
        &[Method::Password, Method::RecoveryCode]
    );
    let again = at_second_factor(&server).await;
    let spent = post(
        &server,
        "recovery",
        Some(&again),
        json!({ "code": RECOVERY }),
    )
    .await;
    refused(
        &spent,
        StatusCode::UNAUTHORIZED,
        "credentials_rejected",
        "spent",
    );
    let used: Vec<_> = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .filter(|record| record.event.kind == AuditKind::RecoveryUsed)
        .collect();
    assert_eq!(used.len(), 1, "one use recorded");
    assert_eq!(used[0].event.user, Some(user));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_code_out_of_place_or_unreadable_is_refused() {
    let server = server(2).await;
    enrolled(&server).await;
    let early = identified(&server, ADA).await;
    for step in ["totp", "recovery"] {
        let code = if step == "totp" {
            current_code()
        } else {
            RECOVERY.to_owned()
        };
        let answered = post(&server, step, Some(&early), json!({ "code": code })).await;
        refused(
            &answered,
            StatusCode::CONFLICT,
            "step_refused",
            "before the password",
        );
    }
    let cookie = at_second_factor(&server).await;
    for (step, code) in [
        ("totp", "12345"),
        ("totp", "abcdef"),
        ("recovery", "not-a-code"),
    ] {
        let answered = post(&server, step, Some(&cookie), json!({ "code": code })).await;
        refused(&answered, StatusCode::BAD_REQUEST, "invalid_request", code);
    }
    assert_eq!(
        signin(&server, &cookie).await.ceremony.verified_methods(),
        &[Method::Password],
        "nothing moved"
    );
    // Neither code was spent by the refused steps: both still sign in.
    let answered = post(
        &server,
        "recovery",
        Some(&cookie),
        json!({ "code": RECOVERY }),
    )
    .await;
    assert_eq!(
        answered.status,
        StatusCode::OK,
        "the recovery code was kept"
    );
    let other = at_second_factor(&server).await;
    let answered = post(
        &server,
        "totp",
        Some(&other),
        json!({ "code": current_code() }),
    )
    .await;
    assert_eq!(
        answered.status,
        StatusCode::OK,
        "the one-time code was kept"
    );
}
