//! The client credentials grant: a confidential client's own token, addressed to a resource it registered, for the
//! scopes it names within its ceiling, naming the client as its subject, with no refresh token — and DPoP-bound when
//! the request carries a proof.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_infrastructure::custody::SigningKey;
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_types::{Algorithm, ClientId, RedirectUri, Resource, ScopeSet, Timestamp};

use crate::routes::Answer;
use crate::token_auth::{ASSERTION_TYPE, Holder, assertion, payload, post_with};
use crate::token_fixture::{API, NOW, REDIRECT, Server, post, server, tenant, uncached};

const FILES: &str = "https://files.example.com/";

/// `machine`, a `private_key_jwt` client registered for client credentials at the API and the file store.
pub(crate) async fn machine(server: &Server) -> SigningKey {
    let (key, _) = SigningKey::generate(Algorithm::Es256).expect("a key");
    let client = NewClient {
        client_id: ClientId::parse("machine").expect("a client id"),
        redirect_uris: vec![RedirectUri::parse(REDIRECT).expect("a redirect URI")],
        scope_ceiling: ScopeSet::parse("api:read api:write").expect("scopes"),
        resources: BTreeSet::from([
            Resource::parse(API).expect("a resource"),
            Resource::parse(FILES).expect("a resource"),
        ]),
        auth_method: AuthMethod::PrivateKeyJwt(Algorithm::Es256),
        grant_types: vec![GrantType::ClientCredentials],
        jwks: vec![key.public_jwk().expect("a JWK")],
        dpop_bound_access_tokens: false,
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
    };
    server
        .storage
        .clients
        .register(
            &tenant("acme"),
            &client,
            Timestamp::from_unix_secs(NOW - 100),
        )
        .await
        .expect("registered");
    key
}

/// The client-credentials request `machine` signs with assertion `jti`, plus `extra`.
fn request(key: &SigningKey, jti: &str, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut pairs = vec![
        ("grant_type".to_owned(), "client_credentials".to_owned()),
        ("client_id".to_owned(), "machine".to_owned()),
        (
            "client_assertion_type".to_owned(),
            ASSERTION_TYPE.to_owned(),
        ),
        (
            "client_assertion".to_owned(),
            assertion(key, "machine", jti),
        ),
    ];
    pairs.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    pairs
}

fn borrowed(pairs: &[(String, String)]) -> Vec<(&str, &str)> {
    pairs
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

fn refused(answer: &Answer, error: &str, case: &str) {
    assert_eq!(
        answer.status,
        StatusCode::BAD_REQUEST,
        "{case}: {}",
        answer.body
    );
    assert_eq!(answer.body["error"], error, "{case}");
    uncached(answer);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_confidential_client_gets_its_own_token_and_no_refresh_token() {
    let server = server(2).await;
    let key = machine(&server).await;
    let pairs = request(&key, "cc-1", &[("scope", "api:read"), ("resource", API)]);
    let answer = post(&server, "acme", &borrowed(&pairs)).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    uncached(&answer);
    assert_eq!(answer.body["token_type"], "Bearer");
    assert_eq!(answer.body["scope"], "api:read");
    assert!(
        answer.body.get("refresh_token").is_none(),
        "{}",
        answer.body
    );
    let claims = payload(&answer);
    assert_eq!(claims["sub"], "machine");
    assert_eq!(claims["client_id"], "machine");
    assert_eq!(claims["aud"], API);
    assert_eq!(claims["scope"], "api:read");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_assertion_sent_without_client_id_authenticates_the_client_it_names() {
    // RFC 7521 §4.2: beside an assertion `client_id` is optional; the assertion's subject names the client.
    let server = server(2).await;
    let key = machine(&server).await;
    let mut pairs = request(
        &key,
        "cc-unnamed",
        &[("scope", "api:read"), ("resource", API)],
    );
    pairs.retain(|(name, _)| name != "client_id");
    let answer = post(&server, "acme", &borrowed(&pairs)).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(payload(&answer)["client_id"], "machine");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_names_its_scopes_within_its_ceiling_at_a_resource_it_registered() {
    let server = server(2).await;
    let key = machine(&server).await;
    for (jti, extra, error, case) in [
        ("cc-2", vec![("resource", API)], "invalid_scope", "no scope"),
        (
            "cc-3",
            vec![("scope", "api:read api:admin"), ("resource", API)],
            "invalid_scope",
            "beyond the ceiling",
        ),
        (
            "cc-4",
            vec![
                ("scope", "api:read"),
                ("resource", "https://other.example.com/"),
            ],
            "invalid_target",
            "a resource not registered",
        ),
        (
            "cc-5",
            vec![("scope", "api:read")],
            "invalid_target",
            "no resource of two",
        ),
    ] {
        let pairs = request(&key, jti, &extra);
        refused(&post(&server, "acme", &borrowed(&pairs)).await, error, case);
    }
    // A public client registered for the code grant only may not ask for its own token.
    let public = post(
        &server,
        "acme",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "portal"),
            ("scope", "api:read"),
        ],
    )
    .await;
    refused(
        &public,
        "unauthorized_client",
        "a client not registered for it",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_proof_binds_a_clients_own_token() {
    let server = server(2).await;
    let key = machine(&server).await;
    let holder = Holder::new(9);
    let pairs = request(&key, "cc-6", &[("scope", "api:write"), ("resource", FILES)]);
    let answer = post_with(&server, &borrowed(&pairs), &[&holder.at_token("cc-6")]).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    assert_eq!(answer.body["token_type"], "DPoP");
    let claims = payload(&answer);
    assert_eq!(claims["cnf"]["jkt"], holder.thumbprint());
    assert_eq!(claims["aud"], FILES);
}
