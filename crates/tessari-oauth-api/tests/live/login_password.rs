//! The password step over a live store: a wrong password and an address with no account are answered alike and
//! counted against the identified address, the client address and the pair; a held key is answered before anything
//! is verified; the right password moves the sign-in on and forgets the address's failures; a step out of place is
//! refused before any hashing.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::signin::SigninKey;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::users::StoredPassword;
use tessari_oauth_types::Timestamp;

use crate::login::{KNOWN, begun, post, refused, register, signin};
use crate::token_fixture::{NOW, Server, passwords, server, tenant};

const RIGHT: &str = "correct horse battery staple";
const WRONG: &str = "incorrect horse battery staple";
/// The address `post` sends from, as the request counter names it.
const SOURCE: &str = "192.0.2.1";

/// Register `email` with the password [`RIGHT`].
async fn with_password(server: &Server, email: &str) {
    let user = register(server, email).await;
    let hash = passwords().hash(RIGHT).await.expect("hashed");
    server
        .storage
        .users
        .set_password(
            &tenant("acme"),
            &user,
            &StoredPassword { hash, pepper: 1 },
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("set");
}

/// A sign-in that has identified `email`, by its cookie.
async fn identified(server: &Server, email: &str) -> String {
    let cookie = begun(server).await;
    let answered = post(server, "identify", Some(&cookie), json!({ "email": email })).await;
    assert_eq!(answered.status, StatusCode::OK);
    cookie
}

/// Count `failures` failed sign-ins against `key` straight in the store.
async fn fail(server: &Server, key: SigninKey, value: &str, failures: u64) {
    for _ in 0..failures {
        server
            .storage
            .throttle
            .signin_failed(&[(key, value)], Timestamp::from_unix_secs(NOW))
            .await
            .expect("counted");
    }
}

fn account(email: &str) -> String {
    passwords().signin_keys().account("acme", email)
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_wrong_password_and_an_unknown_address_are_answered_alike() {
    let server = server(2).await;
    with_password(&server, KNOWN).await;
    let mut answers = Vec::new();
    for email in [KNOWN, "nobody@example.com"] {
        let cookie = identified(&server, email).await;
        let answered = post(
            &server,
            "password",
            Some(&cookie),
            json!({ "password": WRONG }),
        )
        .await;
        refused(
            &answered,
            StatusCode::UNAUTHORIZED,
            "credentials_rejected",
            email,
        );
        assert_eq!(
            signin(&server, &cookie).await.ceremony.verified_methods(),
            &[] as &[Method],
            "{email}: nothing verified"
        );
        answers.push(answered.body);
    }
    assert_eq!(answers[0], answers[1], "one answer for both");
    let refusals: Vec<_> = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .filter(|record| {
            record.event.kind == AuditKind::Refused
                && record.event.reason.as_deref() == Some("credentials_rejected")
        })
        .collect();
    assert_eq!(refusals.len(), 2, "each refusal recorded");
}

/// Fail once through the route for `email` with `key` one failure short of its hold, and assert the route tipped it.
async fn tips(server: &Server, email: &str, key: SigninKey, value: &str, free: u64) {
    fail(server, key, value, free).await;
    let cookie = identified(server, email).await;
    let first = post(
        server,
        "password",
        Some(&cookie),
        json!({ "password": WRONG }),
    )
    .await;
    refused(
        &first,
        StatusCode::UNAUTHORIZED,
        "credentials_rejected",
        email,
    );
    let held = server
        .storage
        .throttle
        .signin_hold(&[(key, value)], Timestamp::from_unix_secs(NOW))
        .await
        .expect("the store answers");
    assert!(held.is_some(), "{email}: the route counted {key:?}");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_failure_is_counted_against_the_address_and_the_pair() {
    let server = server(2).await;
    let email = "account@example.com";
    tips(&server, email, SigninKey::Account, &account(email), 5).await;
    let email = "pair@example.com";
    let pair = passwords()
        .signin_keys()
        .pair("acme", &account(email), WRONG);
    tips(&server, email, SigninKey::Pair, &pair, 3).await;
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_failure_is_counted_against_the_client_address() {
    let server = server(2).await;
    tips(&server, "source@example.com", SigninKey::Source, SOURCE, 50).await;
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_held_address_is_answered_before_anything_is_verified() {
    let server = server(2).await;
    with_password(&server, KNOWN).await;
    fail(&server, SigninKey::Account, &account(KNOWN), 10).await;
    let cookie = identified(&server, KNOWN).await;
    let answered = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    refused(
        &answered,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "held",
    );
    let wait: u64 = answered.headers["retry-after"]
        .to_str()
        .expect("text")
        .parse()
        .expect("seconds");
    assert!(wait > 0, "a wait is stated");
    assert_eq!(
        signin(&server, &cookie).await.ceremony.verified_methods(),
        &[] as &[Method],
        "the right password did not get through a hold"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_right_password_moves_the_sign_in_on_and_forgets_the_failures() {
    let server = server(2).await;
    with_password(&server, KNOWN).await;
    fail(&server, SigninKey::Account, &account(KNOWN), 5).await;
    let cookie = identified(&server, KNOWN).await;
    let answered = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(answered.body, json!({ "next": "complete" }));
    let kept = signin(&server, &cookie).await;
    assert_eq!(kept.ceremony.verified_methods(), &[Method::Password]);
    assert_eq!(
        kept.account,
        Some(account(KNOWN)),
        "the counter key is kept"
    );
    // Six failures in the window would hold the address; after the success only one is remembered.
    let again = identified(&server, KNOWN).await;
    let wrong = post(
        &server,
        "password",
        Some(&again),
        json!({ "password": WRONG }),
    )
    .await;
    refused(
        &wrong,
        StatusCode::UNAUTHORIZED,
        "credentials_rejected",
        "after success",
    );
    let held = server
        .storage
        .throttle
        .signin_hold(
            &[(SigninKey::Account, &account(KNOWN))],
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers");
    assert_eq!(held, None, "the earlier failures were forgotten");

    let enrolled = "grace@example.com";
    with_password(&server, enrolled).await;
    let user = server
        .storage
        .users
        .find_by_email(
            &tenant("acme"),
            &tessari_oauth_types::EmailAddress::parse(enrolled).expect("an address"),
        )
        .await
        .expect("the store answers")
        .expect("registered")
        .user;
    server
        .storage
        .factors
        .enroll_totp(
            &tenant("acme"),
            &server.kek,
            &user,
            &[7; 20],
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("enrolled");
    let cookie = identified(&server, enrolled).await;
    let answered = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    assert_eq!(answered.body, json!({ "next": "second_factor" }));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_password_out_of_place_is_refused() {
    let server = server(2).await;
    with_password(&server, KNOWN).await;
    let fresh = begun(&server).await;
    let early = post(
        &server,
        "password",
        Some(&fresh),
        json!({ "password": RIGHT }),
    )
    .await;
    refused(
        &early,
        StatusCode::CONFLICT,
        "step_refused",
        "before identify",
    );
    let cookie = identified(&server, KNOWN).await;
    let done = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    assert_eq!(done.status, StatusCode::OK);
    let again = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    refused(
        &again,
        StatusCode::CONFLICT,
        "step_refused",
        "after the outcome",
    );
    let wrong = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": WRONG }),
    )
    .await;
    refused(
        &wrong,
        StatusCode::CONFLICT,
        "step_refused",
        "a wrong one after the outcome",
    );
    let none = post(&server, "password", None, json!({ "password": RIGHT })).await;
    refused(&none, StatusCode::GONE, "signin_expired", "no sign-in");
    let unreadable = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "secret": RIGHT }),
    )
    .await;
    refused(
        &unreadable,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "no password field",
    );
}
