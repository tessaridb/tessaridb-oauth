//! DPoP at the token endpoint: a proof binds the access token to its key and is spent once, a client registered as
//! bound is refused without one, a public client's refresh token keeps needing the key it was issued to, and a
//! confidential client's refresh is bound by its authentication instead.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_infrastructure::custody::SigningKey;
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_types::{Algorithm, ClientId, RedirectUri, ScopeSet, Timestamp};

use crate::routes::Answer;
use crate::token_auth::{ASSERTION_TYPE, Holder, assertion, payload, post_with, target};
use crate::token_fixture::{
    NOW, REDIRECT, Server, issue, issuer, post, redemption, server, tenant, uncached,
};

fn issued(answer: &Answer, token_type: &str, case: &str) {
    assert_eq!(answer.status, StatusCode::OK, "{case}: {}", answer.body);
    assert_eq!(answer.body["token_type"], token_type, "{case}");
    uncached(answer);
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

fn refresh_token(answer: &Answer) -> String {
    answer.body["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned()
}

fn refreshing<'a>(client: &'a str, token: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", "refresh_token"),
        ("client_id", client),
        ("refresh_token", token),
    ]
}

async fn register(server: &Server, client: NewClient) {
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
}

fn client(id: &str, auth_method: AuthMethod, jwks: Vec<String>, bound: bool) -> NewClient {
    NewClient {
        client_id: ClientId::parse(id).expect("a client id"),
        redirect_uris: vec![RedirectUri::parse(REDIRECT).expect("a redirect URI")],
        scope_ceiling: ScopeSet::parse("api:read").expect("scopes"),
        resources: BTreeSet::new(),
        auth_method,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        jwks,
        dpop_bound_access_tokens: bound,
        post_logout_redirect_uris: Vec::new(),
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_proof_binds_the_access_token_to_its_key_and_none_leaves_it_bearer() {
    let server = server(2).await;
    let holder = Holder::new(1);
    issue(&server, "acme", "portal", "code-d1", NOW + 60).await;
    let bound = post_with(
        &server,
        &redemption("portal", "code-d1"),
        &[&holder.at_token("d1")],
    )
    .await;
    issued(&bound, "DPoP", "with a proof");
    assert_eq!(payload(&bound)["cnf"]["jkt"], holder.thumbprint());

    issue(&server, "acme", "portal", "code-d2", NOW + 60).await;
    let bearer = post(&server, "acme", &redemption("portal", "code-d2")).await;
    issued(&bearer, "Bearer", "without a proof");
    assert!(payload(&bearer).get("cnf").is_none(), "{}", bearer.body);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_proof_is_spent_once_and_holds_only_for_this_request() {
    let server = server(2).await;
    let holder = Holder::new(2);
    for code in ["code-s1", "code-s2", "code-s3"] {
        issue(&server, "acme", "portal", code, NOW + 60).await;
    }
    let once = holder.at_token("once");
    issued(
        &post_with(&server, &redemption("portal", "code-s1"), &[&once]).await,
        "DPoP",
        "first use",
    );
    refused(
        &post_with(&server, &redemption("portal", "code-s2"), &[&once]).await,
        "invalid_dpop_proof",
        "the same proof again",
    );

    let other_tenant = format!("{}/oauth2/token", issuer("initech"));
    for (case, proofs) in [
        ("another method", vec![holder.proof("m", "GET", &target())]),
        (
            "another target",
            vec![holder.proof("t", "POST", &other_tenant)],
        ),
        (
            "two proofs",
            vec![holder.at_token("two-a"), holder.at_token("two-b")],
        ),
    ] {
        let proofs: Vec<&str> = proofs.iter().map(String::as_str).collect();
        refused(
            &post_with(&server, &redemption("portal", "code-s3"), &proofs).await,
            "invalid_dpop_proof",
            case,
        );
    }
    // A request refused for another reason leaves its proof unspent.
    let kept = holder.at_token("kept");
    refused(
        &post_with(&server, &redemption("portal", "code-unknown"), &[&kept]).await,
        "invalid_grant",
        "an unknown code",
    );
    // None of those refusals spent the code, nor the proof refused with the unknown one.
    issued(
        &post_with(&server, &redemption("portal", "code-s3"), &[&kept]).await,
        "DPoP",
        "after the refusals",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_registered_bound_is_refused_without_a_proof() {
    let server = server(2).await;
    register(
        &server,
        client("signer", AuthMethod::None, Vec::new(), true),
    )
    .await;
    issue(&server, "acme", "signer", "code-b1", NOW + 60).await;
    refused(
        &post(&server, "acme", &redemption("signer", "code-b1")).await,
        "invalid_dpop_proof",
        "no proof",
    );
    let holder = Holder::new(3);
    issued(
        &post_with(
            &server,
            &redemption("signer", "code-b1"),
            &[&holder.at_token("b1")],
        )
        .await,
        "DPoP",
        "with a proof, the code untouched by the refusal",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_public_clients_refresh_token_needs_the_key_it_was_issued_to() {
    let server = server(2).await;
    let (holder, stranger) = (Holder::new(4), Holder::new(5));
    issue(&server, "acme", "portal", "code-r1", NOW + 60).await;
    let first = post_with(
        &server,
        &redemption("portal", "code-r1"),
        &[&holder.at_token("r1")],
    )
    .await;
    issued(&first, "DPoP", "redeemed");
    let token = refresh_token(&first);

    refused(
        &post(&server, "acme", &refreshing("portal", &token)).await,
        "invalid_dpop_proof",
        "no proof",
    );
    refused(
        &post_with(
            &server,
            &refreshing("portal", &token),
            &[&stranger.at_token("r2")],
        )
        .await,
        "invalid_grant",
        "another key",
    );
    let kept = holder.at_token("r3");
    let mut wider = refreshing("portal", &token);
    wider.push(("scope", "api:read api:write"));
    refused(
        &post_with(&server, &wider, &[&kept]).await,
        "invalid_scope",
        "a wider scope",
    );
    // No refusal spent the token or the proof: it rotates now, once, with its own key.
    let rotated = post_with(&server, &refreshing("portal", &token), &[&kept]).await;
    issued(&rotated, "DPoP", "the same key");
    assert_eq!(payload(&rotated)["cnf"]["jkt"], holder.thumbprint());
    let successor = refresh_token(&rotated);
    refused(
        &post(&server, "acme", &refreshing("portal", &successor)).await,
        "invalid_dpop_proof",
        "the successor without a proof",
    );
    issued(
        &post_with(
            &server,
            &refreshing("portal", &successor),
            &[&holder.at_token("r4")],
        )
        .await,
        "DPoP",
        "the successor with the key",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_confidential_clients_refresh_is_not_bound_to_the_proof_key() {
    let server = server(2).await;
    let (key, _) = SigningKey::generate(Algorithm::Es256).expect("a key");
    register(
        &server,
        client(
            "backend",
            AuthMethod::PrivateKeyJwt(Algorithm::Es256),
            vec![key.public_jwk().expect("a JWK")],
            false,
        ),
    )
    .await;
    issue(&server, "acme", "backend", "code-c1", NOW + 60).await;
    let signed = assertion(&key, "backend", "assertion-1");
    let mut pairs = redemption("backend", "code-c1");
    pairs.extend([
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", signed.as_str()),
    ]);
    let holder = Holder::new(6);
    let first = post_with(&server, &pairs, &[&holder.at_token("c1")]).await;
    issued(&first, "DPoP", "redeemed with a proof");
    let token = refresh_token(&first);

    let signed = assertion(&key, "backend", "assertion-2");
    let mut pairs = refreshing("backend", &token);
    pairs.extend([
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", signed.as_str()),
    ]);
    issued(
        &post(&server, "acme", &pairs).await,
        "Bearer",
        "refreshed by client authentication alone",
    );
}
