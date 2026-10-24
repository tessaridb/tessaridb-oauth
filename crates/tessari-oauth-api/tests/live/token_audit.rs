//! Every outcome at the token and revocation endpoints leaves one audit message: what was issued — naming the access
//! token's `jti`, subject, audience and scopes, never the token — what was refused and why, a replayed code, a reused
//! refresh token, and a revocation.

use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_types::{ClientId, ScopeSet, UserId};

use crate::token_auth::{ASSERTION_TYPE, assertion, payload};
use crate::token_client_credentials::machine;
use crate::token_fixture::{API, NOW, Server, USER, issue, post, redemption, server, tenant};

/// The `acme` trail, oldest first.
async fn trail(server: &Server) -> Vec<AuditEvent> {
    server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .map(|record| {
            assert_eq!(record.at.unix_secs(), NOW, "recorded at the request's time");
            record.event
        })
        .collect()
}

fn refresh<'a>(client: &'a str, token: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("grant_type", "refresh_token"),
        ("client_id", client),
        ("refresh_token", token),
    ]
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_issued_code_a_refresh_and_their_reuse_and_replay_are_recorded() {
    let server = server(2).await;
    issue(&server, "acme", "portal", "code-a1", NOW + 60).await;
    let issued = post(&server, "acme", &redemption("portal", "code-a1")).await;
    let claims = payload(&issued);
    let first = issued.body["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();
    let rotated = post(&server, "acme", &refresh("portal", &first)).await;
    let rotated_claims = payload(&rotated);
    // The reuse before the replay: a replay revokes the family, after which the token is refused as revoked.
    post(&server, "acme", &refresh("portal", &first)).await;
    post(&server, "acme", &redemption("portal", "code-a1")).await;

    let portal = || Some(ClientId::parse("portal").expect("a client id"));
    let granted = |kind, claims: &serde_json::Value| AuditEvent {
        client_id: portal(),
        user: Some(UserId::parse(USER).expect("a user id")),
        subject: Some(claims["sub"].as_str().expect("a sub").to_owned()),
        scopes: Some(ScopeSet::parse("api:read").expect("scopes")),
        audience: Some(API.to_owned()),
        jti: Some(claims["jti"].as_str().expect("a jti").to_owned()),
        auth_method: Some("none".to_owned()),
        ..AuditEvent::of(kind)
    };
    assert_eq!(
        trail(&server).await,
        vec![
            granted(AuditKind::IssuedCode, &claims),
            granted(AuditKind::IssuedRefresh, &rotated_claims),
            AuditEvent {
                client_id: portal(),
                reason: Some("RefreshReused".to_owned()),
                ..AuditEvent::of(AuditKind::RefreshReused)
            },
            AuditEvent {
                client_id: portal(),
                reason: Some("CodeReplayed".to_owned()),
                ..AuditEvent::of(AuditKind::CodeReplayed)
            },
        ]
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_refusal_a_revocation_and_a_clients_own_token_are_recorded() {
    let server = server(2).await;
    post(&server, "acme", &redemption("portal", "code-unknown")).await;
    issue(&server, "acme", "portal", "code-b1", NOW + 60).await;
    let issued = post(&server, "acme", &redemption("portal", "code-b1")).await;
    let token = issued.body["refresh_token"]
        .as_str()
        .expect("a refresh token")
        .to_owned();
    crate::token_revoke::revoke(&server, &[("client_id", "portal"), ("token", &token)], None).await;
    let key = machine(&server).await;
    let signed = assertion(&key, "machine", "audit-1");
    let own = post(
        &server,
        "acme",
        &[
            ("grant_type", "client_credentials"),
            ("client_id", "machine"),
            ("scope", "api:read"),
            ("resource", API),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", signed.as_str()),
        ],
    )
    .await;
    let own_claims = payload(&own);

    let events = trail(&server).await;
    let kinds: Vec<AuditKind> = events.iter().map(|event| event.kind).collect();
    assert_eq!(
        kinds,
        vec![
            AuditKind::Refused,
            AuditKind::IssuedCode,
            AuditKind::RevokedByClient,
            AuditKind::IssuedClient
        ]
    );
    let portal = Some(ClientId::parse("portal").expect("a client id"));
    assert_eq!(
        events[0],
        AuditEvent {
            client_id: portal.clone(),
            reason: Some("CodeUnknown".to_owned()),
            ..AuditEvent::of(AuditKind::Refused)
        }
    );
    assert_eq!(
        events[2],
        AuditEvent {
            client_id: portal,
            ..AuditEvent::of(AuditKind::RevokedByClient)
        }
    );
    assert_eq!(
        events[3],
        AuditEvent {
            client_id: Some(ClientId::parse("machine").expect("a client id")),
            subject: Some("machine".to_owned()),
            scopes: Some(ScopeSet::parse("api:read").expect("scopes")),
            audience: Some(API.to_owned()),
            jti: Some(own_claims["jti"].as_str().expect("a jti").to_owned()),
            auth_method: Some("private_key_jwt".to_owned()),
            ..AuditEvent::of(AuditKind::IssuedClient)
        }
    );
}
