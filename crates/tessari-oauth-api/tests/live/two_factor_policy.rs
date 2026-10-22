//! A company's two-factor policy over a live store: under `off` the sign-in asks no second factor, even of an account
//! that holds an authenticator app.

use serde_json::json;
use tessari_oauth_core::two_factor::TwoFactorPolicy;

use crate::login::post;
use crate::login_factors::{ADA, enrolled};
use crate::login_password::{RIGHT, identified};
use crate::token_fixture::{server, tenant};

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn under_off_the_password_alone_completes_a_sign_in_of_an_app_holder() {
    let server = server(2).await;
    enrolled(&server).await;
    server
        .storage
        .policies
        .set_two_factor(&tenant("acme"), TwoFactorPolicy::Off)
        .await
        .expect("set");
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
