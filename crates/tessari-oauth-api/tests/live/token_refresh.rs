//! The refresh grant at the token endpoint: a refresh token rotates into a new one and an access token at most as
//! wide as its grant; a token presented again takes its family with it; a refused refresh leaves the token as it
//! was; and of parallel refreshes of one token at most one is answered.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::StatusCode;
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_types::{ClientId, RedirectUri, ScopeSet, Timestamp};

use crate::routes::Answer;
use crate::token_auth::payload;
use crate::token_fixture::{
    API, NOW, REDIRECT, Server, issue_scoped, post, redemption, server, tenant, uncached,
};

/// A refresh token for `portal`, from the code `secret` granted `scopes`.
async fn refreshable(server: &Server, secret: &str, scopes: &str) -> String {
    issue_scoped(server, "acme", "portal", secret, NOW + 60, scopes).await;
    let answer = post(server, "acme", &redemption("portal", secret)).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    answer.body["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned()
}

/// Present `refresh_token` as `client`, with `extra` parameters.
async fn refresh(
    server: &Server,
    client: &str,
    refresh_token: &str,
    extra: &[(&str, &str)],
) -> Answer {
    let mut pairs = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client),
        ("refresh_token", refresh_token),
    ];
    pairs.extend_from_slice(extra);
    post(server, "acme", &pairs).await
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
async fn a_refresh_rotates_the_token_and_never_widens_the_grant() {
    let server = server(2).await;
    let first = refreshable(&server, "code-r1", "api:read api:write").await;

    let narrowed = refresh(&server, "portal", &first, &[("scope", "api:read")]).await;
    assert_eq!(narrowed.status, StatusCode::OK, "{}", narrowed.body);
    uncached(&narrowed);
    assert_eq!(narrowed.body["token_type"], "Bearer");
    assert_eq!(narrowed.body["scope"], "api:read");
    let claims = payload(&narrowed);
    assert_eq!(claims["scope"], "api:read");
    assert_eq!(claims["aud"], API);
    assert_eq!(claims["client_id"], "portal");
    let second = narrowed.body["refresh_token"]
        .as_str()
        .expect("a successor")
        .to_owned();
    assert_ne!(second, first);

    // The family keeps its grant: the successor refreshes to the whole of it again.
    let whole = refresh(&server, "portal", &second, &[]).await;
    assert_eq!(whole.status, StatusCode::OK, "{}", whole.body);
    assert_eq!(whole.body["scope"], "api:read api:write");
    assert_eq!(payload(&whole)["scope"], "api:read api:write");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_refresh_token_presented_again_revokes_its_family() {
    let server = server(2).await;
    let first = refreshable(&server, "code-r2", "api:read").await;
    let rotated = refresh(&server, "portal", &first, &[]).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let second = rotated.body["refresh_token"]
        .as_str()
        .expect("a successor")
        .to_owned();

    refused(
        &refresh(&server, "portal", &first, &[]).await,
        "invalid_grant",
        "reused",
    );
    refused(
        &refresh(&server, "portal", &second, &[]).await,
        "invalid_grant",
        "successor of a reused token",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_refused_refresh_leaves_the_token_as_it_was() {
    let server = server(2).await;
    let studio = NewClient {
        sector: None,
        client_id: ClientId::parse("studio").expect("a client id"),
        redirect_uris: vec![RedirectUri::parse(REDIRECT).expect("a redirect URI")],
        scope_ceiling: ScopeSet::parse("api:read").expect("scopes"),
        resources: BTreeSet::new(),
        auth_method: AuthMethod::None,
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        jwks: Vec::new(),
        dpop_bound_access_tokens: false,
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
    };
    server
        .storage
        .clients
        .register(
            &tenant("acme"),
            &studio,
            Timestamp::from_unix_secs(NOW - 100),
        )
        .await
        .expect("registered");
    let token = refreshable(&server, "code-r3", "api:read").await;

    let wider = refresh(
        &server,
        "portal",
        &token,
        &[("scope", "api:read api:admin")],
    )
    .await;
    refused(&wider, "invalid_scope", "wider scope");
    let elsewhere = refresh(
        &server,
        "portal",
        &token,
        &[("resource", "https://other.example.com/")],
    )
    .await;
    refused(&elsewhere, "invalid_target", "resource not granted");
    refused(
        &refresh(&server, "studio", &token, &[]).await,
        "invalid_grant",
        "another client's token",
    );
    refused(
        &refresh(&server, "portal", "never-issued", &[]).await,
        "invalid_grant",
        "unknown token",
    );
    let absent = post(
        &server,
        "acme",
        &[("grant_type", "refresh_token"), ("client_id", "portal")],
    )
    .await;
    refused(&absent, "invalid_request", "no refresh token");

    let still = refresh(&server, "portal", &token, &[]).await;
    assert_eq!(still.status, StatusCode::OK, "{}", still.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn of_eight_parallel_refreshes_at_most_one_is_answered() {
    let server = Arc::new(server(8).await);
    let token = Arc::new(refreshable(&server, "code-r4", "api:read").await);
    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (server, token) = (Arc::clone(&server), Arc::clone(&token));
        racers.spawn(async move { refresh(&server, "portal", &token, &[]).await });
    }
    let answers = racers.join_all().await;
    let won: Vec<&Answer> = answers
        .iter()
        .filter(|answer| answer.status == StatusCode::OK)
        .collect();
    let refused_count = answers
        .iter()
        .filter(|answer| {
            answer.status == StatusCode::BAD_REQUEST && answer.body["error"] == "invalid_grant"
        })
        .count();
    assert!(won.len() <= 1, "{} answered with tokens", won.len());
    let seen: Vec<String> = answers
        .iter()
        .map(|answer| format!("{} {}", answer.status, answer.body))
        .collect();
    assert_eq!(won.len() + refused_count, 8, "{seen:?}");
    // The others were reuses, so the winner's successor belongs to a revoked family.
    if let Some(winner) = won.first() {
        let successor = winner.body["refresh_token"].as_str().expect("a successor");
        refused(
            &refresh(&server, "portal", successor, &[]).await,
            "invalid_grant",
            "successor after reuse",
        );
    }
}
