//! A company's two-factor policy over a live store: under `off` the sign-in asks no second factor, even of an account
//! that holds an authenticator app, the portal offers no app, and an app still held is turned off by a password
//! sign-in; under `required` the last second factor is not removed.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::two_factor::TwoFactorPolicy;

use crate::account_factors::{passkey, remove, session};
use crate::account_grants::call;
use crate::login::post;
use crate::login_factors::{ADA, enrolled};
use crate::login_password::{RIGHT, identified, with_password};
use crate::token_fixture::{Server, server, tenant};

async fn under(server: &Server, policy: TwoFactorPolicy) {
    server
        .storage
        .policies
        .set_two_factor(&tenant("acme"), policy)
        .await
        .expect("set");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn under_off_the_password_alone_completes_a_sign_in_of_an_app_holder() {
    let server = server(2).await;
    enrolled(&server).await;
    under(&server, TwoFactorPolicy::Off).await;
    let cookie = identified(&server, ADA).await;
    let answered = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    assert_eq!(answered.body["next"], json!("complete"));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn under_off_no_app_is_offered_and_a_held_one_is_turned_off_by_a_password() {
    let server = server(2).await;
    let fresh = with_password(&server, "hopper@example.com").await;
    let holder = enrolled(&server).await;
    under(&server, TwoFactorPolicy::Off).await;
    let asking = session(&server, &fresh, "hopper", &[Method::Password], 0).await;
    let begun = call(
        &server,
        "POST",
        "totp/begin",
        Some(&asking),
        Some(json!({})),
    )
    .await;
    assert_eq!(begun.status, StatusCode::CONFLICT, "{}", begun.body);
    assert_eq!(begun.body["code"], "not_offered");
    let password_only = session(&server, &holder, "ada", &[Method::Password], 0).await;
    let removed = call(
        &server,
        "POST",
        "totp/remove",
        Some(&password_only),
        Some(json!({})),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.body);
    assert_eq!(removed.body["removed"], true);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn under_required_the_last_second_factor_stays() {
    let server = server(2).await;
    let holder = enrolled(&server).await;
    let keyed = with_password(&server, "lovelace@example.com").await;
    let only = passkey(&server, &keyed, b"lovelaces-key").await;
    under(&server, TwoFactorPolicy::Required).await;
    let with_code = session(
        &server,
        &holder,
        "ada",
        &[Method::Password, Method::Totp],
        0,
    )
    .await;
    let refused = call(
        &server,
        "POST",
        "totp/remove",
        Some(&with_code),
        Some(json!({})),
    )
    .await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert_eq!(refused.body["code"], "second_factor_required");
    let me = call(&server, "GET", "me", Some(&with_code), None).await;
    assert_eq!(me.body["factors"]["totp"], true, "the app is still held");
    let with_key = session(
        &server,
        &keyed,
        "lovelace",
        &[
            Method::Password,
            Method::Passkey {
                user_verified: true,
            },
        ],
        0,
    )
    .await;
    let kept = remove(&server, &with_key, &only).await;
    assert_eq!(kept.status, StatusCode::CONFLICT, "{}", kept.body);
    assert_eq!(kept.body["code"], "second_factor_required");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn under_off_an_app_does_not_shorten_the_password() {
    let server = server(2).await;
    let holder = enrolled(&server).await;
    under(&server, TwoFactorPolicy::Off).await;
    let asking = session(&server, &holder, "ada", &[Method::Password], 0).await;
    let short = call(
        &server,
        "POST",
        "password",
        Some(&asking),
        Some(json!({ "password": "ten chars!" })),
    )
    .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "{}", short.body);
    assert_eq!(short.body["message"], "the password is too short");
}
