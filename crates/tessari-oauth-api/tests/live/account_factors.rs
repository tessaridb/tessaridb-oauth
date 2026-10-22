//! Changing the account's sign-in factors from the account portal: a passkey is removed only by a session whose
//! sign-in is recent and reached the level the account's second factor gives; never another user's, never the
//! account's last way to sign in; and a removal signs out every other session, revokes every refresh family and is
//! recorded.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_types::{SessionSecret, Timestamp, UserId, base64url};

use crate::account_grants::{call, family};
use crate::authenticator::Authenticator;
use crate::login::register;
use crate::login_password::with_password;
use crate::token_fixture::{NOW, Server, server, tenant};

const UV: Method = Method::Passkey {
    user_verified: true,
};

/// Open a session for `user` under the cookie value `value`, signed in with `methods` `ago` seconds before now.
async fn session(
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

/// Register a passkey on `user` from an authenticator holding `credential`, answering its id.
async fn passkey(server: &Server, user: &UserId, credential: &[u8]) -> String {
    let authenticator = Authenticator::new(credential);
    server
        .storage
        .passkeys
        .register(
            &tenant("acme"),
            user,
            &authenticator.registered(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("registered");
    base64url::encode(&authenticator.credential_id)
}

/// The passkey ids `user` holds.
async fn held(server: &Server, user: &UserId) -> Vec<String> {
    server
        .storage
        .passkeys
        .list(&tenant("acme"), user)
        .await
        .expect("the store answers")
        .into_iter()
        .map(|passkey| passkey.id)
        .collect()
}

async fn remove(server: &Server, session: &str, id: &str) -> crate::routes::Answer {
    call(
        server,
        "POST",
        "passkeys/remove",
        Some(session),
        Some(json!({ "id": id })),
    )
    .await
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_removal_needs_a_recent_sign_in_at_the_accounts_level() {
    let server = server(2).await;
    let user = with_password(&server, "liskov@example.com").await;
    let laptop = passkey(&server, &user, b"liskovs-laptop").await;
    passkey(&server, &user, b"liskovs-phone").await;
    let password_only = session(&server, &user, "password-alone", &[Method::Password], 0).await;
    let refused = remove(&server, &password_only, &laptop).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.body);
    assert_eq!(
        refused.body["code"], "reauthentication_required",
        "a passkey is held, a password alone does not change it"
    );
    let an_hour_old = session(
        &server,
        &user,
        "an-hour-old",
        &[Method::Password, Method::Totp],
        3_600,
    )
    .await;
    let refused = remove(&server, &an_hour_old, &laptop).await;
    assert_eq!(
        refused.body["code"], "reauthentication_required",
        "the sign-in is not recent"
    );
    assert_eq!(held(&server, &user).await.len(), 2, "nothing was removed");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_removal_signs_out_the_other_sessions_revokes_every_family_and_is_recorded() {
    let server = server(2).await;
    let user = with_password(&server, "wing@example.com").await;
    let other = with_password(&server, "milner@example.com").await;
    let laptop = passkey(&server, &user, b"wings-laptop").await;
    let phone = passkey(&server, &user, b"wings-phone").await;
    let theirs = passkey(&server, &other, b"milners-key").await;
    let asking = session(&server, &user, "just-signed-in", &[UV], 0).await;
    let elsewhere = session(&server, &user, "a-tablet", &[Method::Password], 600).await;
    family(&server, &user, "refresh-of-wing").await;
    let unknown = remove(&server, &asking, &theirs).await;
    assert_eq!(
        unknown.body,
        json!({ "removed": false }),
        "another user's passkey is not ours to remove"
    );
    assert_eq!(held(&server, &other).await, std::slice::from_ref(&theirs));
    let taken = server
        .storage
        .passkeys
        .remove(&tenant("acme"), &user, &theirs)
        .await
        .expect("the store answers");
    assert!(!taken, "the store itself removes only the owner's passkey");
    assert_eq!(held(&server, &other).await, [theirs]);
    let removed = remove(&server, &asking, &laptop).await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.body);
    assert_eq!(
        removed.body,
        json!({ "removed": true, "sessions": 1, "families": 1, "access_tokens_end_by": NOW + 300 })
    );
    assert_eq!(held(&server, &user).await, [phone]);
    let still = call(&server, "GET", "me", Some(&asking), None).await;
    assert_eq!(
        still.status,
        StatusCode::OK,
        "the asking session stays signed in"
    );
    let gone = call(&server, "GET", "me", Some(&elsewhere), None).await;
    assert_eq!(
        gone.status,
        StatusCode::UNAUTHORIZED,
        "every other session is signed out"
    );
    let recorded: Vec<(Option<String>, Option<u64>)> = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .map(|record| record.event)
        .filter(|event| {
            event.kind == AuditKind::FactorChanged && event.user.as_ref() == Some(&user)
        })
        .map(|event| (event.reason, event.families))
        .collect();
    assert_eq!(recorded, [(Some("passkey_removed".to_owned()), Some(1))]);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_last_way_to_sign_in_is_not_removed() {
    let server = server(2).await;
    let user = register(&server, "hamilton@example.com").await;
    let only = passkey(&server, &user, b"hamiltons-only-key").await;
    let asking = session(&server, &user, "signed-in-by-passkey", &[UV], 0).await;
    let refused = remove(&server, &asking, &only).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert_eq!(refused.body["code"], "last_sign_in_method");
    assert_eq!(held(&server, &user).await, [only]);
}
