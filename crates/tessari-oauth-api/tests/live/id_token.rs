//! The ID token a code redeems for when it was granted `openid`: signed by the tenant's published key as a `JWT`,
//! addressed to the client alone, stating how the user signed in (as the code recorded it) and nothing about who
//! they are beyond the pairwise subject; a code without `openid` redeems for no ID token.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::codes::{CodeAuthentication, IssuedCode};
use tessari_oauth_core::jose::{self, VerifyingKey};
use tessari_oauth_types::{
    Algorithm, AuthorizationCode, Challenge, ClientId, Resource, ScopeSet, Timestamp, UserId,
    base64url,
};

use crate::routes::Answer;
use crate::token_fixture::{
    API, NOW, REDIRECT, Server, USER, VERIFIER, issuer, post, redemption, server, tenant,
};

const SIGNED_IN: u64 = NOW - 3_600;

/// Issue the code `secret` to `portal` granting `scopes`, behind a password and TOTP sign-in an hour ago.
async fn issue(server: &Server, secret: &str, scopes: &str, nonce: Option<&str>) {
    let issued = IssuedCode {
        tenant: tenant("acme"),
        client_id: ClientId::parse("portal").expect("a client id"),
        user: UserId::parse(USER).expect("a user id"),
        redirect_uri: REDIRECT.to_owned(),
        challenge: Challenge::of(VERIFIER).expect("a challenge"),
        scopes: ScopeSet::parse(scopes).expect("scopes"),
        resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
        expires_at: Timestamp::from_unix_secs(NOW + 60),
        authentication: CodeAuthentication {
            auth_time: Timestamp::from_unix_secs(SIGNED_IN),
            methods: vec![Method::Password, Method::Totp],
            sid: "c2Vzc2lvbi1wdWJsaWMtaWQ".to_owned(),
        },
        nonce: nonce.map(str::to_owned),
    };
    server
        .storage
        .codes
        .issue(&AuthorizationCode::from_secret(secret), &issued)
        .await
        .expect("issued");
}

/// The verified claims of the `field` token in `answer`, which must carry the type `typ`.
fn verified(
    server: &Server,
    answer: &Answer,
    field: &str,
    typ: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let compact = answer.body[field].as_str().expect("a token");
    let key = VerifyingKey::from_jwk(&server.published, Algorithm::Es256).expect("a public key");
    let verified =
        jose::verify(compact, Algorithm::Es256, &[key]).expect("signed by the published key");
    assert_eq!(verified.typ.as_deref(), Some(typ));
    serde_json::from_slice(&verified.payload).expect("a claims object")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_openid_code_redeems_for_an_id_token_stating_the_sign_in_and_nothing_else() {
    let server = server(2).await;
    issue(
        &server,
        "code-openid",
        "openid api:read",
        Some("n-0S6_WzA2Mj"),
    )
    .await;
    let answered = post(&server, "acme", &redemption("portal", "code-openid")).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    let access = verified(&server, &answered, "access_token", "at+jwt");
    let claims = verified(&server, &answered, "id_token", "JWT");
    let names: BTreeSet<&str> = claims.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "sid",
            "at_hash"
        ]),
        "authentication facts only"
    );
    assert_eq!(claims["iss"], issuer("acme"));
    assert_eq!(claims["sub"], access["sub"], "the same pairwise subject");
    assert_eq!(claims["aud"], "portal", "the client alone");
    assert_eq!(claims["iat"], NOW);
    assert_eq!(claims["exp"], NOW + 300);
    assert_eq!(claims["auth_time"], SIGNED_IN);
    assert_eq!(claims["nonce"], "n-0S6_WzA2Mj");
    assert_eq!(claims["acr"], "urn:tessaridb:acr:mfa");
    assert_eq!(claims["amr"], serde_json::json!(["pwd", "otp", "mfa"]));
    assert_eq!(claims["sid"], "c2Vzc2lvbi1wdWJsaWMtaWQ");
    let token = answered.body["access_token"].as_str().expect("a token");
    let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
    let (left, _) = digest.as_ref().split_at(16);
    assert_eq!(claims["at_hash"], base64url::encode(left));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_openid_or_a_nonce_nothing_is_said_that_was_not_asked() {
    let server = server(2).await;
    issue(&server, "code-plain", "api:read", None).await;
    issue(&server, "code-no-nonce", "openid", None).await;
    let plain = post(&server, "acme", &redemption("portal", "code-plain")).await;
    assert_eq!(plain.status, StatusCode::OK, "{}", plain.body);
    assert!(
        plain.body.get("id_token").is_none(),
        "no openid, no ID token"
    );
    let answered = post(&server, "acme", &redemption("portal", "code-no-nonce")).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    let claims = verified(&server, &answered, "id_token", "JWT");
    assert!(!claims.contains_key("nonce"), "no nonce was sent");
}
