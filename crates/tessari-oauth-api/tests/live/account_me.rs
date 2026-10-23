//! The account portal's own view: a signed-in user reads the address they sign in with, whether it is verified, and
//! what their sign-in factors are (a password or not, an authenticator app or not, how many recovery codes are left,
//! and their passkeys), never a secret and never another user's.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_infrastructure::custody::recovery_digest;
use tessari_oauth_types::{EmailAddress, Timestamp, UserId, base64url};

use crate::account_grants::call;
use crate::authenticator::Authenticator;
use crate::authorize_resume::signed_in;
use crate::token_fixture::{NOW, Server, server, tenant};

/// Register a passkey on `user` from an authenticator holding `credential`, answering its id as the list shows it.
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

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_a_session_nothing_is_said() {
    let server = server(2).await;
    let answered = call(&server, "GET", "me", None, None).await;
    assert_eq!(answered.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answered.body["code"], "session_required");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_user_reads_their_address_and_factors_and_nobody_elses() {
    let server = server(2).await;
    let (_, session, user) = signed_in(&server, "noyce@example.com").await;
    let (_, _, other) = signed_in(&server, "kilby@example.com").await;
    passkey(&server, &other, b"another-users-key").await;
    let verified = server
        .storage
        .users
        .find_by_email(
            &tenant("acme"),
            &EmailAddress::parse("noyce@example.com").expect("an address"),
        )
        .await
        .expect("the store answers")
        .expect("the account")
        .email_verified;
    let answered = call(&server, "GET", "me", Some(&session), None).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    assert_eq!(
        answered.body,
        json!({
            "email": "noyce@example.com",
            "email_verified": verified,
            "factors": { "password": true, "totp": false, "recovery_codes": 0, "passkeys": [] },
            "two_factor": "optional",
            "profile": { "name": null, "given_name": null, "family_name": null },
        })
    );
    let at = Timestamp::from_unix_secs(NOW);
    server
        .storage
        .factors
        .enroll_totp(&tenant("acme"), &server.kek, &user, &[9; 20], at)
        .await
        .expect("enrolled");
    let digests = ["7K3M-9QXZ-AB12-CD34", "8L4N-0RYA-BC23-DE45"]
        .map(|code| recovery_digest(code).expect("a recovery code"));
    server
        .storage
        .factors
        .issue_recovery_codes(&tenant("acme"), &user, &digests, at)
        .await
        .expect("issued");
    let id = passkey(&server, &user, b"noyces-laptop-key").await;
    let answered = call(&server, "GET", "me", Some(&session), None).await;
    assert_eq!(
        answered.body["factors"],
        json!({
            "password": true,
            "totp": true,
            "recovery_codes": 2,
            "passkeys": [{ "id": id, "created_at": NOW, "synced": true }],
        }),
        "the user's own factors, no secret among them"
    );
}
