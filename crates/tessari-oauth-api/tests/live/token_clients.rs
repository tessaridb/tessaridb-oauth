//! The token endpoint for a confidential client and under its own request limit: a client assertion authenticates
//! once and never again, and token requests are counted apart from the metadata reads.

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tessari_oauth_api::public_router;
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_infrastructure::custody::SigningKey;
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_types::{Algorithm, ClientId, RedirectUri, ScopeSet, Timestamp};
use tower::ServiceExt;

use crate::routes::{Answer, answer, header};
use crate::token_auth::{ASSERTION_TYPE, assertion};
use crate::token_fixture::{
    NOW, REDIRECT, Server, issue, post, redemption, server, state, tenant, uncached,
};

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_assertion_authenticates_once() {
    let server = server(2).await;
    let (key, _) = SigningKey::generate(Algorithm::Es256).expect("a key");
    let backend = NewClient {
        client_id: ClientId::parse("backend").expect("a client id"),
        redirect_uris: vec![RedirectUri::parse(REDIRECT).expect("a redirect URI")],
        scope_ceiling: ScopeSet::parse("api:read").expect("scopes"),
        resources: BTreeSet::new(),
        auth_method: AuthMethod::PrivateKeyJwt(Algorithm::Es256),
        grant_types: vec![GrantType::AuthorizationCode],
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
            &backend,
            Timestamp::from_unix_secs(NOW - 100),
        )
        .await
        .expect("registered");
    for code in ["code-one", "code-two"] {
        issue(&server, "acme", "backend", code, NOW + 60).await;
    }
    let first_assertion = assertion(&key, "backend", "assertion-1");
    let one = post(
        &server,
        "acme",
        &authenticated("code-one", &first_assertion),
    )
    .await;
    assert_eq!(one.status, StatusCode::OK, "{}", one.body);

    // The same assertion again, for another code: the client is not authenticated, and the code is not spent.
    let again = post(
        &server,
        "acme",
        &authenticated("code-two", &first_assertion),
    )
    .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED, "{}", again.body);
    assert_eq!(again.body["error"], "invalid_client");
    uncached(&again);

    let second_assertion = assertion(&key, "backend", "assertion-2");
    let two = post(
        &server,
        "acme",
        &authenticated("code-two", &second_assertion),
    )
    .await;
    assert_eq!(two.status, StatusCode::OK, "{}", two.body);
}

/// The redemption of `code` by `backend`, authenticated with `signed`.
fn authenticated<'a>(code: &'a str, signed: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut pairs = redemption("backend", code);
    pairs.extend([
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", signed),
    ]);
    pairs
}

async fn call(server: &Server, limit: Limit, request: Request<Body>) -> Answer {
    let response = public_router(state(server, limit))
        .oneshot(request)
        .await
        .expect("the router answers");
    answer(response).await
}

fn token_request() -> Request<Body> {
    Request::post("/acme/oauth2/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("grant_type=authorization_code&client_id=portal"))
        .expect("a request")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn token_requests_are_counted_under_their_own_limit() {
    let server = server(2).await;
    let one = Limit {
        requests: NonZeroU64::new(1).expect("non-zero"),
        window_secs: NonZeroU64::new(60).expect("non-zero"),
    };
    let first = call(&server, one, token_request()).await;
    assert_eq!(first.status, StatusCode::BAD_REQUEST, "{}", first.body);
    assert_eq!(header(&first, "x-ratelimit-class"), "token");
    assert_eq!(header(&first, "x-ratelimit-limit"), "1");

    let second = call(&server, one, token_request()).await;
    assert_eq!(
        second.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        second.body
    );
    assert_eq!(header(&second, "x-ratelimit-class"), "token");

    // The metadata reads are counted apart, so the spent token limit does not refuse them.
    let read = Request::get("/acme/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .expect("a request");
    let metadata = call(&server, one, read).await;
    assert_eq!(metadata.status, StatusCode::OK, "{}", metadata.body);
    assert_eq!(header(&metadata, "x-ratelimit-class"), "read");
}
