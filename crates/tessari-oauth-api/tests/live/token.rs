//! The token endpoint end to end: a code redeemed once for an access token carrying exactly its claims, a code
//! presented again taking its refresh family with it, and parallel redemptions of which at most one is answered.

use std::sync::Arc;

use axum::http::StatusCode;
use tessari_oauth_core::jose::{self, VerifyingKey};
use tessari_oauth_storage::refresh::{RefreshGrant, Rotation, RotationRefusal};
use tessari_oauth_types::{
    Algorithm, AuthorizationCode, ClientId, RefreshToken, Resource, ScopeSet, Timestamp, UserId,
};

use crate::routes::Answer;
use crate::token_fixture::{
    API, NOW, Server, USER, issue, issuer, post, redemption, server, tenant, uncached,
};

/// The claims of the access token in `answer`, verified under `acme`'s published key.
fn claims(server: &Server, answer: &Answer) -> serde_json::Map<String, serde_json::Value> {
    let compact = answer.body["access_token"]
        .as_str()
        .expect("an access token");
    let key = VerifyingKey::from_jwk(&server.published, Algorithm::Es256).expect("a public key");
    let verified =
        jose::verify(compact, Algorithm::Es256, &[key]).expect("signed by the published key");
    assert_eq!(verified.typ.as_deref(), Some("at+jwt"));
    serde_json::from_slice(&verified.payload).expect("a claims object")
}

async fn rotation(server: &Server, refresh_token: &str) -> Rotation {
    server
        .storage
        .refresh
        .rotate(
            &tenant("acme"),
            &RefreshToken::from_secret(refresh_token),
            &RefreshToken::from_secret("successor"),
            &ClientId::parse("portal").expect("a client id"),
            Timestamp::from_unix_secs(NOW + 1),
        )
        .await
        .expect("the store answers")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_code_redeems_for_an_access_token_carrying_exactly_its_claims() {
    let server = server(2).await;
    issue(&server, "acme", "portal", "code-portal", NOW + 60).await;
    issue(&server, "acme", "kiosk", "code-kiosk", NOW + 60).await;

    let portal = post(&server, "acme", &redemption("portal", "code-portal")).await;
    assert_eq!(portal.status, StatusCode::OK, "{}", portal.body);
    uncached(&portal);
    assert_eq!(portal.body["token_type"], "Bearer");
    assert_eq!(portal.body["expires_in"], 300);
    assert_eq!(portal.body["scope"], "api:read");
    assert!(
        portal.body["refresh_token"]
            .as_str()
            .is_some_and(|token| token.len() >= 43)
    );
    let claims_portal = claims(&server, &portal);
    let names: Vec<&str> = claims_portal.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "aud",
            "client_id",
            "exp",
            "iat",
            "iss",
            "jti",
            "scope",
            "sub"
        ]
    );
    assert_eq!(claims_portal["iss"], issuer("acme"));
    assert_eq!(claims_portal["aud"], API);
    assert_eq!(claims_portal["client_id"], "portal");
    assert_eq!(claims_portal["scope"], "api:read");
    assert_eq!(claims_portal["iat"], NOW);
    assert_eq!(claims_portal["exp"], NOW + 300);

    // A client not registered for refresh tokens gets none, and knows the same user by another subject.
    let kiosk = post(&server, "acme", &redemption("kiosk", "code-kiosk")).await;
    assert_eq!(kiosk.status, StatusCode::OK, "{}", kiosk.body);
    assert!(kiosk.body.get("refresh_token").is_none(), "{}", kiosk.body);
    let claims_kiosk = claims(&server, &kiosk);
    let (sub_portal, sub_kiosk) = (&claims_portal["sub"], &claims_kiosk["sub"]);
    assert_ne!(sub_portal, sub_kiosk);
    for sub in [sub_portal, sub_kiosk] {
        assert!(!sub.as_str().expect("a subject").contains(USER), "{sub}");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_code_presented_again_is_refused_and_takes_its_refresh_family_with_it() {
    let server = server(2).await;
    issue(&server, "acme", "portal", "code-twice", NOW + 60).await;
    let first = post(&server, "acme", &redemption("portal", "code-twice")).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let refresh_token = first.body["refresh_token"]
        .as_str()
        .expect("a refresh token");

    let again = post(&server, "acme", &redemption("portal", "code-twice")).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(again.body["error"], "invalid_grant");
    uncached(&again);
    assert_eq!(
        rotation(&server, refresh_token).await,
        Rotation::Refused(RotationRefusal::FamilyRevoked)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn of_eight_parallel_redemptions_at_most_one_is_answered_with_tokens() {
    let server = Arc::new(server(8).await);
    issue(&server, "acme", "portal", "code-raced", NOW + 60).await;
    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let server = Arc::clone(&server);
        racers
            .spawn(async move { post(&server, "acme", &redemption("portal", "code-raced")).await });
    }
    let answers: Vec<Answer> = racers.join_all().await;
    let won: Vec<&Answer> = answers
        .iter()
        .filter(|answer| answer.status == StatusCode::OK)
        .collect();
    let refused = answers
        .iter()
        .filter(|answer| {
            answer.status == StatusCode::BAD_REQUEST && answer.body["error"] == "invalid_grant"
        })
        .count();
    assert!(won.len() <= 1, "{} answered with tokens", won.len());
    assert_eq!(won.len() + refused, 8);
    // The others were replays, so whatever the winner was given is already revoked.
    if let Some(winner) = won.first() {
        let refresh_token = winner.body["refresh_token"]
            .as_str()
            .expect("a refresh token");
        assert_eq!(
            rotation(&server, refresh_token).await,
            Rotation::Refused(RotationRefusal::FamilyRevoked)
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_code_whose_family_a_replay_already_revoked_issues_nothing() {
    let server = server(2).await;
    issue(&server, "acme", "portal", "code-late", NOW + 60).await;
    // A replay of the code landed before its first redemption started the family: the family is recorded revoked.
    let grant = RefreshGrant {
        tenant: tenant("acme"),
        user: UserId::parse(USER).expect("a user id"),
        client_id: ClientId::parse("portal").expect("a client id"),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        resources: [Resource::parse(API).expect("a resource")].into(),
    };
    let family = AuthorizationCode::from_secret("code-late").digest();
    server
        .storage
        .refresh
        .revoke_for_replay(&grant, &family, Timestamp::from_unix_secs(NOW))
        .await
        .expect("recorded revoked");

    let late = post(&server, "acme", &redemption("portal", "code-late")).await;
    assert_eq!(late.status, StatusCode::BAD_REQUEST, "{}", late.body);
    assert_eq!(late.body["error"], "invalid_grant");
    assert!(late.body.get("access_token").is_none());
    uncached(&late);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_tenant_with_no_key_to_sign_with_starts_no_refresh_family() {
    let server = server(2).await;
    let acme = tenant("acme");
    for key in server.storage.keys.live(&acme).await.expect("the keys") {
        server
            .storage
            .keys
            .compromise(&acme, &key.kid)
            .await
            .expect("withdrawn");
    }
    issue(&server, "acme", "portal", "code-unsigned", NOW + 60).await;
    let unsigned = post(&server, "acme", &redemption("portal", "code-unsigned")).await;
    assert_eq!(
        unsigned.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        unsigned.body
    );
    assert_eq!(unsigned.body["code"], "unavailable");

    // No family was started from the code: one can still be started under its id.
    let grant = RefreshGrant {
        tenant: acme,
        user: UserId::parse(USER).expect("a user id"),
        client_id: ClientId::parse("portal").expect("a client id"),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        resources: [Resource::parse(API).expect("a resource")].into(),
    };
    let family = AuthorizationCode::from_secret("code-unsigned").digest();
    server
        .storage
        .refresh
        .start(
            &RefreshToken::from_secret("probe"),
            &grant,
            &family,
            Timestamp::from_unix_secs(NOW + 1),
        )
        .await
        .expect("no family existed under the code's id");
}
