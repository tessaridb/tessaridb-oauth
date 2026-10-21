//! UserInfo (OpenID Connect Core §5.3): a token addressed to it and carrying `openid` is answered with its subject
//! and nothing more; any other token is refused with one `invalid_token` shape, a token without `openid` with
//! `insufficient_scope`, a bound token only under DPoP with a proof over it spent once — and every refusal is recorded.

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tessari_oauth_api::public_router;
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_core::codes::IssuedCode;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_types::{
    AuthorizationCode, Challenge, ClientId, RedirectUri, Resource, ScopeSet, Timestamp, UserId,
    base64url,
};
use tower::ServiceExt;

use crate::routes::{Answer, answer, header};
use crate::token_auth::{Holder, payload, post_with};
use crate::token_fixture::{
    API, NOW, REDIRECT, Server, USER, VERIFIER, issue, issuer, plenty, post, redemption, server,
    state, tenant, uncached,
};

fn userinfo() -> String {
    format!("{}/oauth2/userinfo", issuer("acme"))
}

/// `reader`: a public client of `acme` that may address UserInfo and the API.
async fn register_reader(server: &Server) {
    let reader = NewClient {
        client_id: ClientId::parse("reader").expect("a client id"),
        redirect_uris: vec![RedirectUri::parse(REDIRECT).expect("a redirect URI")],
        scope_ceiling: ScopeSet::parse("openid profile api:read").expect("scopes"),
        resources: BTreeSet::from([
            Resource::parse(userinfo()).expect("a resource"),
            Resource::parse(API).expect("a resource"),
        ]),
        auth_method: AuthMethod::None,
        grant_types: vec![GrantType::AuthorizationCode],
        jwks: Vec::new(),
        dpop_bound_access_tokens: false,
    };
    server
        .storage
        .clients
        .register(
            &tenant("acme"),
            &reader,
            Timestamp::from_unix_secs(NOW - 100),
        )
        .await
        .expect("registered");
}

/// Issue `code` to `reader` for `scopes` at `resource`.
async fn issue_for(server: &Server, code: &str, scopes: &str, resource: &str) {
    let issued = IssuedCode {
        tenant: tenant("acme"),
        client_id: ClientId::parse("reader").expect("a client id"),
        user: UserId::parse(USER).expect("a user id"),
        redirect_uri: REDIRECT.to_owned(),
        challenge: Challenge::of(VERIFIER).expect("a challenge"),
        scopes: ScopeSet::parse(scopes).expect("scopes"),
        resources: BTreeSet::from([Resource::parse(resource).expect("a resource")]),
        expires_at: Timestamp::from_unix_secs(NOW + 60),
    };
    server
        .storage
        .codes
        .issue(&AuthorizationCode::from_secret(code), &issued)
        .await
        .expect("issued");
}

fn access_token(answer: &Answer) -> String {
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    answer.body["access_token"]
        .as_str()
        .expect("an access token")
        .to_owned()
}

/// A token from `reader` for `scopes` at `resource`, redeemed through the token endpoint.
async fn token_for(server: &Server, code: &str, scopes: &str, resource: &str) -> String {
    issue_for(server, code, scopes, resource).await;
    access_token(&post(server, "acme", &redemption("reader", code)).await)
}

/// Call `acme`'s UserInfo with `method`, the given `authorization` and `dpop` headers.
async fn call(server: &Server, method: &str, authorization: Option<&str>, dpop: &[&str]) -> Answer {
    let mut request = Request::builder()
        .method(method)
        .uri("/acme/oauth2/userinfo");
    if let Some(credentials) = authorization {
        request = request.header("authorization", credentials);
    }
    for proof in dpop {
        request = request.header("dpop", *proof);
    }
    let response = public_router(state(server, plenty()))
        .oneshot(request.body(Body::empty()).expect("a request"))
        .await
        .expect("the router answers");
    answer(response).await
}

/// The refusal carried only the challenge, `challenge` exactly, and was never cached.
fn challenged(answer: &Answer, status: StatusCode, challenge: &str, case: &str) {
    assert_eq!(answer.status, status, "{case}: {}", answer.body);
    assert_eq!(header(answer, "www-authenticate"), challenge, "{case}");
    uncached(answer);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_token_for_userinfo_with_openid_is_answered_with_its_subject_alone() {
    let server = server(2).await;
    register_reader(&server).await;
    let token = token_for(&server, "code-u1", "openid profile", &userinfo()).await;
    let middle = token.split('.').nth(1).expect("three segments");
    let claims: serde_json::Value =
        serde_json::from_slice(&base64url::decode(middle).expect("base64url")).expect("JSON");
    let subject = claims["sub"].as_str().expect("a subject").to_owned();
    assert!(
        !subject.is_empty() && subject != USER,
        "a pairwise subject: {subject}"
    );
    for method in ["GET", "POST"] {
        let answered = call(&server, method, Some(&format!("Bearer {token}")), &[]).await;
        assert_eq!(
            answered.status,
            StatusCode::OK,
            "{method}: {}",
            answered.body
        );
        assert_eq!(
            answered.body,
            serde_json::json!({ "sub": subject }),
            "{method}: the subject and nothing more"
        );
        assert_eq!(header(&answered, "content-type"), "application/json");
        assert_eq!(header(&answered, "x-ratelimit-class"), "read");
        uncached(&answered);
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn any_other_token_is_refused_with_one_shape_and_every_refusal_is_recorded() {
    let server = server(2).await;
    register_reader(&server).await;
    let invalid = r#"Bearer error="invalid_token""#;
    challenged(
        &call(&server, "GET", None, &[]).await,
        StatusCode::UNAUTHORIZED,
        "Bearer",
        "no credentials",
    );
    challenged(
        &call(&server, "GET", Some("Basic cmVhZGVyOng="), &[]).await,
        StatusCode::UNAUTHORIZED,
        "Bearer",
        "another scheme",
    );
    let for_the_api = token_for(&server, "code-u2", "openid", API).await;
    challenged(
        &call(&server, "GET", Some(&format!("Bearer {for_the_api}")), &[]).await,
        StatusCode::UNAUTHORIZED,
        invalid,
        "a token for another resource",
    );
    challenged(
        &call(&server, "GET", Some("Bearer not.a.token"), &[]).await,
        StatusCode::UNAUTHORIZED,
        invalid,
        "not a token",
    );
    let without_openid = token_for(&server, "code-u3", "profile", &userinfo()).await;
    challenged(
        &call(
            &server,
            "GET",
            Some(&format!("Bearer {without_openid}")),
            &[],
        )
        .await,
        StatusCode::FORBIDDEN,
        r#"Bearer error="insufficient_scope", scope="openid""#,
        "no openid",
    );
    issue(&server, "initech", "portal", "code-u4", NOW + 60).await;
    let elsewhere = access_token(&post(&server, "initech", &redemption("portal", "code-u4")).await);
    challenged(
        &call(&server, "GET", Some(&format!("Bearer {elsewhere}")), &[]).await,
        StatusCode::UNAUTHORIZED,
        invalid,
        "another tenant's token",
    );
    let reasons: Vec<Option<String>> = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .map(|record| record.event)
        .filter(|event: &AuditEvent| event.kind == AuditKind::Refused)
        .map(|event| event.reason)
        .collect();
    assert_eq!(
        reasons,
        [
            "AccessTokenMissing",
            "AccessTokenMissing",
            "AccessTokenAudience",
            "AccessTokenUnverified",
            "ScopeWithoutOpenId",
            "AccessTokenUnverified",
        ]
        .map(|reason| Some(reason.to_owned())),
        "each refusal with its reason, in order"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_bound_token_is_answered_under_dpop_with_a_proof_over_it_spent_once() {
    let server = server(2).await;
    register_reader(&server).await;
    let holder = Holder::new(3);
    issue_for(&server, "code-u5", "openid", &userinfo()).await;
    let bound = post_with(
        &server,
        &redemption("reader", "code-u5"),
        &[&holder.at_token("t-5")],
    )
    .await;
    assert_eq!(payload(&bound)["cnf"]["jkt"], holder.thumbprint());
    let token = access_token(&bound);
    let proof = holder.over("u-1", "GET", &userinfo(), &token);
    let scheme = format!("DPoP {token}");
    let answered = call(&server, "GET", Some(&scheme), &[&proof]).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    assert!(answered.body["sub"].is_string());
    challenged(
        &call(&server, "GET", Some(&scheme), &[&proof]).await,
        StatusCode::UNAUTHORIZED,
        r#"DPoP error="invalid_dpop_proof""#,
        "the same proof again",
    );
    challenged(
        &call(&server, "GET", Some(&format!("Bearer {token}")), &[]).await,
        StatusCode::UNAUTHORIZED,
        r#"Bearer error="invalid_token""#,
        "a bound token as a bearer token",
    );
    challenged(
        &call(
            &server,
            "GET",
            Some(&scheme),
            &[&holder.over("u-2", "GET", &userinfo(), "another token")],
        )
        .await,
        StatusCode::UNAUTHORIZED,
        r#"DPoP error="invalid_dpop_proof""#,
        "a proof over another token",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_token_whose_key_was_withdrawn_is_refused() {
    let server = server(2).await;
    register_reader(&server).await;
    let token = token_for(&server, "code-u6", "openid", &userinfo()).await;
    let bearer = format!("Bearer {token}");
    assert_eq!(
        call(&server, "GET", Some(&bearer), &[]).await.status,
        StatusCode::OK
    );
    let stored = server
        .storage
        .keys
        .live(&tenant("acme"))
        .await
        .expect("the keys read");
    for key in &stored {
        server
            .storage
            .keys
            .compromise(&tenant("acme"), &key.kid)
            .await
            .expect("withdrawn");
    }
    challenged(
        &call(&server, "GET", Some(&bearer), &[]).await,
        StatusCode::UNAUTHORIZED,
        r#"Bearer error="invalid_token""#,
        "signed by a withdrawn key",
    );
}
