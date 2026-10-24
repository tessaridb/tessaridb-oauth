//! What a passkey step does to the failure counts over a live store: an assertion that proves nothing is counted
//! against the client address it came from, and one that signs in forgets the identified address's failures.

use std::net::SocketAddr;

use axum::http::StatusCode;
use tessari_oauth_core::signin::SigninKey;
use tessari_oauth_types::Timestamp;

use crate::authenticator::{Authenticator, ORIGIN, UP, UV};
use crate::login::{begun, post_from, refused};
use crate::login_factors::ADA;
use crate::login_passkey::options;
use crate::login_passkey_assertion::{sign, with_passkey};
use crate::login_password::{account, fail, identified};
use crate::token_fixture::{NOW, Server, plenty, server};

/// Whether `key` holding `value` is held now.
async fn held(server: &Server, key: SigninKey, value: &str) -> bool {
    server
        .storage
        .throttle
        .signin_hold(&[(key, value)], Timestamp::from_unix_secs(NOW))
        .await
        .expect("the store answers")
        .is_some()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_assertion_that_proves_nothing_is_counted_against_the_client_address() {
    let server = server(2).await;
    let device = Authenticator::new(b"credential-8");
    with_passkey(&server, &device).await;
    let stranger = Authenticator::new(b"credential-unregistered");
    let peer = "198.51.100.7";
    // One short of the client address's hold.
    fail(&server, SigninKey::Source, peer, 50).await;
    let cookie = begun(&server).await;
    let asked = options(&server, Some(&cookie)).await;
    let challenge = asked.body["challenge"].as_str().expect("a challenge");
    let body = stranger.assert(challenge, ORIGIN, UP | UV, 0).to_string();
    let from: SocketAddr = format!("{peer}:50000").parse().expect("an address");
    let answered = post_from(&server, plenty(), from, "passkey", Some(&cookie), body).await;
    refused(
        &answered,
        StatusCode::UNAUTHORIZED,
        "credentials_rejected",
        "an unregistered credential",
    );
    assert!(
        held(&server, SigninKey::Source, peer).await,
        "the route counted the client address"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_passkey_sign_in_forgets_the_identified_address_failures() {
    let server = server(2).await;
    let device = Authenticator::new(b"credential-9");
    with_passkey(&server, &device).await;
    let cookie = identified(&server, ADA).await;
    // One short of the address's hold.
    fail(&server, SigninKey::Account, &account(ADA), 5).await;
    let answered = sign(&server, &cookie, &device, ORIGIN, UP | UV, 0).await;
    assert_eq!(answered.status, StatusCode::OK);
    fail(&server, SigninKey::Account, &account(ADA), 1).await;
    assert!(
        !held(&server, SigninKey::Account, &account(ADA)).await,
        "the failures before the sign-in were forgotten"
    );
}
