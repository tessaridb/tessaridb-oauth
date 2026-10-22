//! The passkey steps over a live store: options name a fresh challenge kept for one assertion and this relying
//! party, with no list of credentials, for a known and an unknown address alike.

use axum::http::StatusCode;
use serde_json::{Value, json};
use tessari_oauth_storage::passkeys::Ceremony;
use tessari_oauth_types::{Timestamp, base64url};

use crate::login::{KNOWN, begun, post, refused};
use crate::login_factors::{at_second_factor, current_code, enrolled};
use crate::login_password::{identified, with_password};
use crate::token_fixture::{NOW, Server, server, tenant};

/// Ask the sign-in under `cookie` for passkey options.
async fn options(server: &Server, cookie: Option<&str>) -> crate::routes::Answer {
    post(server, "passkey/options", cookie, json!({})).await
}

/// Spend the challenge `answered` names, as an assertion would; whether it was kept for one.
async fn kept_for_assertion(server: &Server, answered: &Value) -> bool {
    let challenge =
        base64url::decode(answered["challenge"].as_str().expect("a challenge")).expect("base64url");
    assert_eq!(challenge.len(), 32, "256 bits");
    server
        .storage
        .passkeys
        .spend_challenge(
            &tenant("acme"),
            &challenge,
            Ceremony::Assertion,
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .is_some()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn options_name_a_kept_challenge_and_no_credentials_for_any_address() {
    let server = server(2).await;
    with_password(&server, KNOWN).await;
    let fresh = begun(&server).await;
    let first = options(&server, Some(&fresh)).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body["rp_id"], "id.example.com", "the issuer's host");
    assert_eq!(first.body["user_verification"], "required");
    assert_eq!(first.body["timeout_ms"], 300_000);
    assert!(kept_for_assertion(&server, &first.body).await, "kept");
    let again = options(&server, Some(&fresh)).await;
    assert_ne!(
        again.body["challenge"], first.body["challenge"],
        "each ask draws its own"
    );
    let mut shapes = Vec::new();
    for email in [KNOWN, "nobody@example.com"] {
        let cookie = identified(&server, email).await;
        let answered = options(&server, Some(&cookie)).await;
        assert_eq!(answered.status, StatusCode::OK, "{email}");
        let mut keys: Vec<&String> = answered
            .body
            .as_object()
            .expect("an object")
            .keys()
            .collect();
        keys.sort();
        shapes.push((
            keys.into_iter().cloned().collect::<Vec<_>>(),
            answered.body["user_verification"].clone(),
        ));
    }
    assert_eq!(shapes[0], shapes[1], "one shape for both addresses");
    assert!(
        !shapes[0].0.iter().any(|key| key.contains("allow")),
        "no list of credentials: {:?}",
        shapes[0].0
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn options_follow_the_stage_and_need_a_sign_in() {
    let server = server(2).await;
    enrolled(&server).await;
    let none = options(&server, None).await;
    refused(&none, StatusCode::GONE, "signin_expired", "no sign-in");
    let cookie = at_second_factor(&server).await;
    let second = options(&server, Some(&cookie)).await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(
        second.body["user_verification"], "preferred",
        "a second factor needs presence, not verification"
    );
    let done = post(
        &server,
        "totp",
        Some(&cookie),
        json!({ "code": current_code() }),
    )
    .await;
    assert_eq!(done.body, json!({ "next": "complete" }));
    let after = options(&server, Some(&cookie)).await;
    refused(
        &after,
        StatusCode::CONFLICT,
        "step_refused",
        "after the outcome",
    );
}
