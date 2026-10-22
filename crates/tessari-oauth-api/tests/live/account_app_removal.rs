//! Turning the authenticator app off from the account portal: only a recent sign-in that used the app may do it;
//! the app and its recovery codes go, the other sessions end, every refresh family is revoked, and the next sign-in
//! asks no code.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_types::{SessionSecret, Timestamp, UserId};

use crate::account_grants::call;
use crate::login::post;
use crate::login_password::{identified, with_password};
use crate::token_fixture::{NOW, Server, server, tenant};

async fn session(server: &Server, user: &UserId, value: &str, methods: &[Method]) -> String {
    server
        .storage
        .sessions
        .create(
            &tenant("acme"),
            &SessionSecret::from_secret(value.to_owned()),
            user,
            methods,
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("opened");
    value.to_owned()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_app_is_turned_off_only_by_a_sign_in_that_used_it() {
    let server = server(2).await;
    let user = with_password(&server, "turing@example.com").await;
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
    let remove = |session: String| {
        let server = &server;
        async move {
            call(
                server,
                "POST",
                "totp/remove",
                Some(&session),
                Some(json!({})),
            )
            .await
        }
    };
    let weak = session(&server, &user, "password-only", &[Method::Password]).await;
    assert_eq!(remove(weak).await.body["code"], "reauthentication_required");
    let asking = session(
        &server,
        &user,
        "with-a-code",
        &[Method::Password, Method::Totp],
    )
    .await;
    let other = session(
        &server,
        &user,
        "a-tablet",
        &[Method::Password, Method::Totp],
    )
    .await;
    let removed = remove(asking.clone()).await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.body);
    assert_eq!(removed.body["removed"], true);
    assert_eq!(
        removed.body["sessions"], 2,
        "the password-only session and the tablet"
    );
    assert_eq!(removed.body["access_tokens_end_by"], NOW + 300);
    let me = call(&server, "GET", "me", Some(&asking), None).await;
    assert_eq!(me.body["factors"]["totp"], false);
    assert_eq!(me.body["factors"]["recovery_codes"], 0);
    assert_eq!(
        call(&server, "GET", "me", Some(&other), None).await.status,
        StatusCode::UNAUTHORIZED
    );
    let again = remove(asking).await;
    assert_eq!(
        again.body,
        json!({ "removed": false }),
        "nothing left to turn off"
    );
    let cookie = identified(&server, "turing@example.com").await;
    let step = post(
        &server,
        "password",
        Some(&cookie),
        json!({ "password": crate::login_password::RIGHT }),
    )
    .await;
    assert_eq!(step.body["next"], "complete", "no code is asked any more");
}
