//! The profile a signed-in user keeps: three names, set and replaced whole at `account/api/profile`, read back on the
//! account, each name bounded — and nothing set without the session.

use axum::http::StatusCode;
use serde_json::json;
use tessari_oauth_core::authentication::Method;

use crate::account_grants::call;
use crate::account_password::session;
use crate::login_password::with_password;
use crate::token_fixture::server;

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_user_sets_their_profile_and_reads_it_on_their_account() {
    let server = server(2).await;
    let user = with_password(&server, "ada@example.com").await;
    let signed_in = session(&server, &user, "profile-session", &[Method::Password], 0).await;
    let names = json!({ "name": " Ada Lovelace ", "given_name": "Ada", "family_name": "Lovelace" });
    let set = call(&server, "POST", "profile", Some(&signed_in), Some(names)).await;
    assert_eq!(set.status, StatusCode::OK, "{}", set.body);
    let kept = json!({ "name": "Ada Lovelace", "given_name": "Ada", "family_name": "Lovelace" });
    assert_eq!(set.body["profile"], kept, "kept trimmed");
    let me = call(&server, "GET", "me", Some(&signed_in), None).await;
    assert_eq!(me.body["profile"], kept);

    let refused = call(
        &server,
        "POST",
        "profile",
        Some(&signed_in),
        Some(json!({ "name": "Ada\u{7}" })),
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(refused.body["code"], "profile_rejected");
    let cleared = call(
        &server,
        "POST",
        "profile",
        Some(&signed_in),
        Some(json!({})),
    )
    .await;
    assert_eq!(cleared.status, StatusCode::OK, "{}", cleared.body);
    assert_eq!(
        call(&server, "GET", "me", Some(&signed_in), None)
            .await
            .body["profile"],
        json!({ "name": null, "given_name": null, "family_name": null }),
        "replaced whole: what is not sent is cleared"
    );

    let anonymous = call(
        &server,
        "POST",
        "profile",
        None,
        Some(json!({ "name": "Mallory" })),
    )
    .await;
    assert_eq!(
        anonymous.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        anonymous.body
    );
    assert_eq!(anonymous.body["code"], "session_required");
}
