//! A finished sign-in over a live store: the step that completes it opens a session under a cookie of its own, drawn
//! fresh, clears the sign-in cookie, says where the authorization continues, records the sign-in, and leaves no
//! sign-in behind to take another step from.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::{Method, assess};
use tessari_oauth_storage::sessions::Session;
use tessari_oauth_storage::signins::Purpose;
use tessari_oauth_types::{SessionSecret, Timestamp, UserId};

use crate::authenticator::{Authenticator, ORIGIN, UP, UV};
use crate::login::{begun, post, refused};
use crate::login_passkey_assertion::{sign, with_passkey};
use crate::login_password::{RIGHT, identified, with_password};
use crate::routes::Answer;
use crate::token_fixture::{NOW, Server, issuer, server, tenant};

const SESSION_COOKIE: &str = "__Host-tessari-session";
const LOGIN_COOKIE: &str = "__Host-tessari-login";

/// The `Set-Cookie` value naming `name` in `answered`.
fn set_cookie<'a>(answered: &'a Answer, name: &str) -> &'a str {
    answered
        .headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} is set"))
}

/// The session value a completing answer set.
pub(crate) fn session_value(answered: &Answer) -> String {
    let set = set_cookie(answered, SESSION_COOKIE);
    let (pair, _) = set.split_once(';').expect("attributes follow the value");
    pair.split_once('=').expect("a value").1.to_owned()
}

/// The session a completing answer opened, read straight from the store.
pub(crate) async fn session(server: &Server, answered: &Answer) -> Session {
    server
        .storage
        .sessions
        .find(
            &tenant("acme"),
            &SessionSecret::from_secret(session_value(answered)),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .expect("the session is there")
}

/// Assert `answered` completed the sign-in, and answer the session it opened, which established what `methods`
/// establish.
pub(crate) async fn completed(server: &Server, answered: &Answer, methods: &[Method]) -> Session {
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(answered.body["next"], "complete");
    let opened = session(server, answered).await;
    assert_eq!(
        Some(&opened.assessment),
        assess(methods).as_ref(),
        "{methods:?}"
    );
    opened
}

/// How many `signed_in` records the trail holds for `user`.
async fn signed_in(server: &Server, user: &UserId) -> usize {
    server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .filter(|record| {
            record.event.kind.as_str() == "signed_in" && record.event.user.as_ref() == Some(user)
        })
        .count()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_completing_step_opens_a_session_and_ends_the_sign_in() {
    let server = server(2).await;
    let user = with_password(&server, "grace@example.com").await;
    let cookie = identified(&server, "grace@example.com").await;
    let Purpose::Authorization(interaction) = crate::login::signin(&server, &cookie).await.purpose
    else {
        panic!("a sign-in begun for an authorization answers it");
    };
    let answered = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(
        answered.body,
        json!({
            "next": "complete",
            "continue": format!("{}/oauth2/authorize/resume?interaction={interaction}", issuer("acme")),
        })
    );
    let set = set_cookie(&answered, SESSION_COOKIE);
    for attribute in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=604800",
    ] {
        assert!(
            set.split("; ").any(|part| part == attribute),
            "{attribute} in {set}"
        );
    }
    let cleared = set_cookie(&answered, LOGIN_COOKIE);
    assert!(
        cleared.starts_with(&format!("{LOGIN_COOKIE}=;")) && cleared.contains("Max-Age=0"),
        "the sign-in cookie is cleared: {cleared}"
    );
    assert_ne!(session_value(&answered), cookie, "a value of its own");
    let opened = session(&server, &answered).await;
    assert_eq!(opened.user, user);
    assert_eq!(opened.auth_time, Timestamp::from_unix_secs(NOW));
    assert_eq!(opened.assessment.amr, ["pwd"]);
    assert_eq!(signed_in(&server, &user).await, 1, "recorded once");
    let again = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    refused(
        &again,
        StatusCode::GONE,
        "signin_expired",
        "the sign-in is finished",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn each_completion_draws_a_session_of_its_own() {
    let server = server(2).await;
    with_password(&server, "hopper@example.com").await;
    let mut values = Vec::new();
    for _ in 0..2 {
        let cookie = identified(&server, "hopper@example.com").await;
        let answered = post(
            &server,
            "password",
            Some(&cookie),
            json!({ "password": RIGHT }),
        )
        .await;
        assert_eq!(answered.body["next"], "complete");
        values.push(session_value(&answered));
    }
    assert_ne!(values[0], values[1]);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_passkey_that_completes_the_sign_in_opens_its_session() {
    let server = server(2).await;
    let device = Authenticator::new(b"credential-10");
    let user = with_passkey(&server, &device).await;
    let answered = sign(&server, &begun(&server).await, &device, ORIGIN, UP | UV, 0).await;
    assert_eq!(answered.body["next"], "complete");
    let opened = session(&server, &answered).await;
    assert_eq!(opened.user, user);
    let expected = assess(&[Method::Passkey {
        user_verified: true,
    }])
    .expect("an assessment");
    assert_eq!(opened.assessment, expected);
    assert!(!expected.amr.is_empty(), "the passkey names a method");
    assert_eq!(signed_in(&server, &user).await, 1);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_sign_in_begun_for_the_account_page_opens_a_session_and_continues_there() {
    let server = server(2).await;
    let user = with_password(&server, "hamming@example.com").await;
    let begun = post(&server, "begin", None, json!({ "account": true })).await;
    assert_eq!(begun.status, StatusCode::OK, "{}", begun.body);
    assert_eq!(begun.body["next"], "identify");
    let set = set_cookie(&begun, LOGIN_COOKIE);
    let (pair, _) = set.split_once(';').expect("attributes follow the value");
    let cookie = pair.split_once('=').expect("a value").1.to_owned();
    let identified = post(
        &server,
        "identify",
        Some(&cookie),
        json!({ "email": "hamming@example.com" }),
    )
    .await;
    assert_eq!(identified.status, StatusCode::OK, "{}", identified.body);
    let done = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    let opened = completed(&server, &done, &[Method::Password]).await;
    assert_eq!(opened.user, user);
    assert_eq!(
        done.body["continue"],
        format!("{}/account", issuer("acme")),
        "no authorization is resumed; the account page is"
    );
    for asked in [
        json!({}),
        json!({ "account": false }),
        json!({ "account": true, "interaction": "abc" }),
    ] {
        let refused = post(&server, "begin", None, asked.clone()).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{asked}");
        assert_eq!(refused.body["code"], "invalid_request", "{asked}");
    }
}
