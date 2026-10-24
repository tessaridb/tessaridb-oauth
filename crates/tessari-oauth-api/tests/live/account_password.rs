//! Changing the password from the account portal: only a session whose sign-in is recent and reached the account's
//! level may change it; the new value meets the rules for how the account signs in (longer when it is the only
//! factor) and is not one of the account's own words; a change replaces the stored hash, signs out every other
//! session, revokes every refresh family and is recorded without the value.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_infrastructure::custody::Verdict;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::refresh::{Rotation, RotationRefusal};
use tessari_oauth_types::{ClientId, RefreshToken, SessionSecret, Timestamp, UserId};

use crate::account_grants::{call, family};
use crate::login_password::{RIGHT, with_password};
use crate::token_fixture::{NOW, Server, passwords, server, tenant};

const NEW: &str = "a much longer phrase than before";

/// Open a session for `user` under the cookie value `value`, signed in with `methods` `ago` seconds before now.
pub(crate) async fn session(
    server: &Server,
    user: &UserId,
    value: &str,
    methods: &[Method],
    ago: u64,
) -> String {
    server
        .storage
        .sessions
        .create(
            &tenant("acme"),
            &SessionSecret::from_secret(value.to_owned()),
            user,
            methods,
            Timestamp::from_unix_secs(NOW.checked_sub(ago).expect("an instant")),
        )
        .await
        .expect("opened");
    value.to_owned()
}

async fn change(server: &Server, session: &str, password: &str) -> crate::routes::Answer {
    call(
        server,
        "POST",
        "password",
        Some(session),
        Some(json!({ "password": password })),
    )
    .await
}

/// Whether `password` is what `user` now signs in with.
async fn signs_in_with(server: &Server, user: &UserId, password: &str) -> bool {
    let stored = server
        .storage
        .users
        .password(&tenant("acme"), user)
        .await
        .expect("the store answers")
        .expect("a password");
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
async fn a_password_is_changed_by_a_recent_sign_in_to_a_value_the_rules_accept() {
    let server = server(2).await;
    let user = with_password(&server, "hopper@example.com").await;
    let stale = session(&server, &user, "an-hour-ago", &[Method::Password], 3600).await;
    let refused = change(&server, &stale, NEW).await;
    assert_eq!(refused.body["code"], "reauthentication_required");
    let asking = session(&server, &user, "just-now", &[Method::Password], 0).await;
    let elsewhere = session(&server, &user, "a-laptop", &[Method::Password], 60).await;
    let issued = family(&server, &user, "refresh-of-hopper").await;
    let short = change(&server, &asking, "ten chars!").await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST, "{}", short.body);
    assert_eq!(
        short.body["code"], "password_rejected",
        "the only factor needs fifteen characters"
    );
    assert_eq!(
        short.body["message"], "the password is too short",
        "the account page reads the rule from this message"
    );
    let own = change(&server, &asking, "Hopper@Example.com").await;
    assert_eq!(
        own.body["code"], "password_rejected",
        "the account's own address is guessed first"
    );
    assert!(
        signs_in_with(&server, &user, RIGHT).await,
        "nothing changed yet"
    );
    let changed = change(&server, &asking, NEW).await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(
        changed.body["sessions"], 2,
        "the laptop and the hour-old session"
    );
    assert_eq!(changed.body["families"], 1);
    assert_eq!(changed.body["access_tokens_end_by"], NOW + 300);
    assert!(signs_in_with(&server, &user, NEW).await);
    assert!(!signs_in_with(&server, &user, RIGHT).await);
    assert_eq!(
        call(&server, "GET", "me", Some(&elsewhere), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&server, "GET", "me", Some(&asking), None).await.status,
        StatusCode::OK,
        "the session that changed it stays"
    );
    let rotated = server
        .storage
        .refresh
        .rotate(
            &tenant("acme"),
            &issued,
            &RefreshToken::from_secret("refresh-next".to_owned()),
            &ClientId::parse("portal").expect("a client id"),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers");
    assert_eq!(rotated, Rotation::Refused(RotationRefusal::FamilyRevoked));
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads");
    assert!(trail.iter().any(|event| {
        event.event.kind == AuditKind::FactorChanged
            && event.event.reason.as_deref() == Some("password_changed")
            && event.event.user.as_ref() == Some(&user)
    }));
    let recorded = format!("{trail:?}");
    assert!(!recorded.contains(NEW), "the value is never recorded");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_account_with_an_app_may_hold_a_shorter_password() {
    let server = server(2).await;
    let user = with_password(&server, "lamport@example.com").await;
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
    let asking = session(
        &server,
        &user,
        "with-a-code",
        &[Method::Password, Method::Totp],
        0,
    )
    .await;
    let changed = change(&server, &asking, "8 chars!").await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert!(signs_in_with(&server, &user, "8 chars!").await);
    let shorter = change(&server, &asking, "7 chars").await;
    assert_eq!(shorter.body["code"], "password_rejected");
}
