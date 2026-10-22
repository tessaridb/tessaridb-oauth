//! The passkey assertion step over a live store: an assertion that verified its user is a whole sign-in, with or
//! without an address, a present one stands as a second factor, every assertion that proves nothing is answered
//! alike, counted and recorded, a counter that does not move forward is a suspected clone, and a held address or a
//! step out of place is refused before any check.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::ceremony::Identity;
use tessari_oauth_core::signin::SigninKey;
use tessari_oauth_types::{Timestamp, UserId};

use crate::authenticator::{Authenticator, ORIGIN, UP, UV};
use crate::login::{begun, post, refused, register, signin};
use crate::login_factors::{ADA, at_second_factor, enrolled};
use crate::login_passkey::options;
use crate::login_password::{account, fail, identified};
use crate::token_fixture::{NOW, Server, server, tenant};

/// `ADA` with a password, a one-time code factor, and the passkey `authenticator` holds.
pub(crate) async fn with_passkey(server: &Server, authenticator: &Authenticator) -> UserId {
    let user = enrolled(server).await;
    server
        .storage
        .passkeys
        .register(
            &tenant("acme"),
            &user,
            &authenticator.registered(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("registered");
    user
}

/// Ask for options on the sign-in under `cookie` and answer them with `authenticator`.
pub(crate) async fn sign(
    server: &Server,
    cookie: &str,
    authenticator: &Authenticator,
    origin: &str,
    flags: u8,
    count: u32,
) -> crate::routes::Answer {
    let asked = options(server, Some(cookie)).await;
    let challenge = asked.body["challenge"].as_str().expect("a challenge");
    let body = authenticator.assert(challenge, origin, flags, count);
    post(server, "passkey", Some(cookie), body).await
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_passkey_that_verified_its_user_is_a_whole_sign_in_with_or_without_an_address() {
    let server = server(2).await;
    let device = Authenticator::new(b"credential-1");
    let user = with_passkey(&server, &device).await;
    for (cookie, case) in [
        (begun(&server).await, "nobody identified"),
        (identified(&server, ADA).await, "the address identified"),
    ] {
        let answered = sign(&server, &cookie, &device, ORIGIN, UP | UV, 0).await;
        assert_eq!(answered.status, StatusCode::OK, "{case}");
        assert_eq!(answered.body, json!({ "next": "complete" }), "{case}");
        let kept = signin(&server, &cookie).await;
        assert_eq!(
            kept.ceremony.verified_methods(),
            &[Method::Passkey {
                user_verified: true
            }],
            "{case}"
        );
        // Identified first, the account keeps the second factor it has; found by its passkey, it needs none.
        let expected = Identity::Known {
            user: user.clone(),
            second_factor: case == "the address identified",
        };
        assert_eq!(kept.ceremony.identity(), Some(&expected), "{case}");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_passkey_stands_as_a_second_factor_with_presence_alone() {
    let server = server(2).await;
    let device = Authenticator::new(b"credential-2");
    with_passkey(&server, &device).await;
    let cookie = at_second_factor(&server).await;
    let answered = sign(&server, &cookie, &device, ORIGIN, UP, 0).await;
    assert_eq!(answered.body, json!({ "next": "complete" }));
    assert_eq!(
        signin(&server, &cookie).await.ceremony.verified_methods(),
        &[
            Method::Password,
            Method::Passkey {
                user_verified: false
            }
        ]
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_assertion_that_proves_nothing_is_answered_alike_and_counted() {
    let server = server(2).await;
    let device = Authenticator::new(b"credential-3");
    with_passkey(&server, &device).await;
    let stranger = Authenticator::new(b"credential-unknown");
    let mut forged = Authenticator::new(b"credential-3");
    forged.credential_id = device.credential_id.clone();
    let other = Authenticator::new(b"credential-4");
    let someone = register(&server, "someone@example.com").await;
    server
        .storage
        .passkeys
        .register(
            &tenant("acme"),
            &someone,
            &other.registered(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("registered");
    let cases: [(&Authenticator, &str, u8, bool, &str); 5] = [
        (
            &device,
            "https://elsewhere.example.com",
            UP | UV,
            false,
            "another origin",
        ),
        (
            &stranger,
            ORIGIN,
            UP | UV,
            false,
            "a credential nobody registered",
        ),
        (&forged, ORIGIN, UP | UV, false, "signed by another key"),
        (
            &device,
            ORIGIN,
            UP,
            false,
            "no verification for a whole sign-in",
        ),
        (
            &other,
            ORIGIN,
            UP | UV,
            true,
            "another account's passkey for the identified address",
        ),
    ];
    for (authenticator, origin, flags, identify, case) in cases {
        let cookie = if identify {
            identified(&server, ADA).await
        } else {
            begun(&server).await
        };
        let answered = sign(&server, &cookie, authenticator, origin, flags, 0).await;
        refused(
            &answered,
            StatusCode::UNAUTHORIZED,
            "credentials_rejected",
            case,
        );
        assert_eq!(
            signin(&server, &cookie).await.ceremony.verified_methods(),
            &[] as &[Method],
            "{case}"
        );
    }
    // A challenge is answered once.
    let cookie = begun(&server).await;
    let asked = options(&server, Some(&cookie)).await;
    let challenge = asked.body["challenge"]
        .as_str()
        .expect("a challenge")
        .to_owned();
    let first = post(
        &server,
        "passkey",
        Some(&cookie),
        device.assert(&challenge, ORIGIN, UP | UV, 1),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    let again = begun(&server).await;
    let replayed = post(
        &server,
        "passkey",
        Some(&again),
        device.assert(&challenge, ORIGIN, UP | UV, 2),
    )
    .await;
    refused(
        &replayed,
        StatusCode::UNAUTHORIZED,
        "credentials_rejected",
        "a spent challenge",
    );
    let rejected = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .filter(|record| record.event.reason.as_deref() == Some("credentials_rejected"))
        .count();
    assert_eq!(rejected, 6, "each recorded");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_counter_that_does_not_move_forward_is_refused_and_recorded() {
    let server = server(2).await;
    let device = Authenticator::new(b"credential-5");
    with_passkey(&server, &device).await;
    let first = sign(&server, &begun(&server).await, &device, ORIGIN, UP | UV, 5).await;
    assert_eq!(first.status, StatusCode::OK);
    let cloned = sign(&server, &begun(&server).await, &device, ORIGIN, UP | UV, 5).await;
    refused(
        &cloned,
        StatusCode::UNAUTHORIZED,
        "credentials_rejected",
        "the same counter",
    );
    let suspected = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .filter(|record| record.event.reason.as_deref() == Some("passkey_clone_suspected"))
        .count();
    assert_eq!(suspected, 1, "recorded as a suspected clone");
    let synced = Authenticator::new(b"credential-6");
    with_passkey_for(&server, &synced, "zero@example.com").await;
    for _ in 0..2 {
        let answered = sign(&server, &begun(&server).await, &synced, ORIGIN, UP | UV, 0).await;
        assert_eq!(
            answered.status,
            StatusCode::OK,
            "a counter that stays at zero is not a clone"
        );
    }
}

/// Register `authenticator`'s passkey for a fresh account `email`.
async fn with_passkey_for(server: &Server, authenticator: &Authenticator, email: &str) {
    let user = register(server, email).await;
    server
        .storage
        .passkeys
        .register(
            &tenant("acme"),
            &user,
            &authenticator.registered(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("registered");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_held_address_or_a_step_out_of_place_is_refused_before_any_check() {
    let server = server(2).await;
    let device = Authenticator::new(b"credential-7");
    with_passkey(&server, &device).await;
    let cookie = identified(&server, ADA).await;
    fail(&server, SigninKey::Account, &account(ADA), 10).await;
    let held = sign(&server, &cookie, &device, ORIGIN, UP | UV, 0).await;
    refused(&held, StatusCode::TOO_MANY_REQUESTS, "rate_limited", "held");
    server
        .storage
        .throttle
        .signin_succeeded(&account(ADA))
        .await
        .expect("forgotten");
    let done = sign(&server, &cookie, &device, ORIGIN, UP | UV, 0).await;
    assert_eq!(
        done.status,
        StatusCode::OK,
        "the challenge of the held step was a new one"
    );
    let after = post(
        &server,
        "passkey",
        Some(&cookie),
        device.assert("AAAA", ORIGIN, UP | UV, 9),
    )
    .await;
    refused(
        &after,
        StatusCode::CONFLICT,
        "step_refused",
        "after the outcome",
    );
    let none = post(
        &server,
        "passkey",
        None,
        device.assert("AAAA", ORIGIN, UP | UV, 9),
    )
    .await;
    refused(&none, StatusCode::GONE, "signin_expired", "no sign-in");
    let fresh = begun(&server).await;
    let unreadable = post(
        &server,
        "passkey",
        Some(&fresh),
        json!({ "credential_id": "x" }),
    )
    .await;
    refused(
        &unreadable,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "unreadable",
    );
}
