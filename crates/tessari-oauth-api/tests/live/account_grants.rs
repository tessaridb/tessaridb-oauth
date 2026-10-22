//! The account portal's grant list, where a user takes back what they granted: a signed-in user sees the grants
//! they gave, standing ones only and their own only, and ends one; ending it ends the consent and every refresh
//! family of that grant, records both, and says when the access tokens already issued stop working. Without a
//! session the surface answers 401 and says nothing.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_core::consents::{ConsentRequest, Coverage};
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::refresh::{RefreshGrant, Rotation, RotationRefusal};
use tessari_oauth_types::{ClientId, RefreshToken, Resource, ScopeSet, Timestamp, UserId};
use tower::ServiceExt;

use crate::authorize_resume::{consented, signed_in};
use crate::routes::{Answer, answer, header, protected};
use crate::token_fixture::{
    API, BROWSER_COOKIE, NOW, Server, plenty, server, state, tenant, uncached,
};

const SESSION_COOKIE: &str = "__Host-tessari-session";

/// Call `method` `path` on `acme`'s account API as the holder of `session`, with `body` as JSON when given.
pub(crate) async fn call(
    server: &Server,
    method: &str,
    path: &str,
    session: Option<&str>,
    body: Option<serde_json::Value>,
) -> Answer {
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/acme/account/api/{path}"))
        .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 9], 50_000))));
    request = match session {
        Some(value) => request.header(
            "cookie",
            format!("{BROWSER_COOKIE}; {SESSION_COOKIE}={value}"),
        ),
        None => request.header("cookie", BROWSER_COOKIE),
    };
    let body = match body {
        Some(value) => {
            request = request.header("content-type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = public_router(state(server, plenty()))
        .oneshot(request.body(body).expect("a request"))
        .await
        .expect("the router answers");
    let answered = answer(response).await;
    protected(&answered);
    uncached(&answered);
    assert_eq!(header(&answered, "x-ratelimit-class"), "account");
    answered
}

fn portal() -> ClientId {
    ClientId::parse("portal").expect("a client id")
}

/// Start a refresh family for `user` at `portal`, answering its first token.
pub(crate) async fn family(server: &Server, user: &UserId, secret: &str) -> RefreshToken {
    let first = RefreshToken::from_secret(secret.to_owned());
    let grant = RefreshGrant {
        tenant: tenant("acme"),
        user: user.clone(),
        client_id: portal(),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        resources: [Resource::parse(API).expect("a resource")].into(),
        bound_to: None,
    };
    server
        .storage
        .refresh
        .start(
            &first,
            &grant,
            &format!("family-{secret}"),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("started");
    first
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_a_session_the_surface_says_sign_in_and_nothing_else() {
    let server = server(2).await;
    for (method, path, body) in [
        ("GET", "grants", None),
        (
            "POST",
            "grants/revoke",
            Some(json!({ "client_id": "portal" })),
        ),
    ] {
        let answered = call(&server, method, path, None, body.clone()).await;
        assert_eq!(answered.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(answered.body["code"], "session_required");
        let lapsed = call(&server, method, path, Some("a-session-nobody-opened"), body).await;
        assert_eq!(lapsed.status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_user_sees_their_own_standing_grants_only() {
    let server = server(2).await;
    let (_, session, user) = signed_in(&server, "hopper@example.com").await;
    let (_, other_session, _) = signed_in(&server, "lovelace@example.com").await;
    let listed = call(&server, "GET", "grants", Some(&session), None).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(listed.body, json!({ "grants": [] }), "nothing granted yet");
    consented(&server, &user).await;
    let listed = call(&server, "GET", "grants", Some(&session), None).await;
    assert_eq!(
        listed.body,
        json!({ "grants": [{
            "client_id": "portal",
            "scopes": ["api:read"],
            "resources": [API],
            "granted_at": NOW,
        }] })
    );
    let theirs = call(&server, "GET", "grants", Some(&other_session), None).await;
    assert_eq!(
        theirs.body,
        json!({ "grants": [] }),
        "another user's grant is not shown"
    );
    let ended = call(
        &server,
        "POST",
        "grants/revoke",
        Some(&other_session),
        Some(json!({ "client_id": "portal" })),
    )
    .await;
    assert_eq!(
        ended.body["revoked"], false,
        "another user cannot end it: their own grant to portal does not stand"
    );
    let still = server
        .storage
        .consents
        .check(
            &tenant("acme"),
            &user,
            &portal(),
            &ConsentRequest {
                scopes: ScopeSet::parse("api:read").expect("scopes"),
                resources: [Resource::parse(API).expect("a resource")].into(),
            },
            1,
        )
        .await
        .expect("the store answers");
    assert_eq!(still, Coverage::Covered, "the first user's grant stands");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn ending_a_grant_ends_its_consent_and_families_records_both_and_states_the_timing() {
    let server = server(2).await;
    let (_, session, user) = signed_in(&server, "conway@example.com").await;
    consented(&server, &user).await;
    let held = family(&server, &user, "refresh-held-by-portal").await;
    let ended = call(
        &server,
        "POST",
        "grants/revoke",
        Some(&session),
        Some(json!({ "client_id": "portal" })),
    )
    .await;
    assert_eq!(ended.status, StatusCode::OK, "{}", ended.body);
    assert_eq!(
        ended.body,
        json!({
            "revoked": true,
            "families": 1,
            "access_tokens_end_by": NOW + 300,
        })
    );
    let listed = call(&server, "GET", "grants", Some(&session), None).await;
    assert_eq!(
        listed.body,
        json!({ "grants": [] }),
        "an ended grant leaves the list"
    );
    let coverage = server
        .storage
        .consents
        .check(
            &tenant("acme"),
            &user,
            &portal(),
            &ConsentRequest {
                scopes: ScopeSet::parse("api:read").expect("scopes"),
                resources: [Resource::parse(API).expect("a resource")].into(),
            },
            1,
        )
        .await
        .expect("the store answers");
    assert!(
        matches!(coverage, Coverage::Prompt { .. }),
        "the user is asked again"
    );
    let rotated = server
        .storage
        .refresh
        .rotate(
            &tenant("acme"),
            &held,
            &RefreshToken::from_secret("refresh-next".to_owned()),
            &portal(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers");
    assert_eq!(rotated, Rotation::Refused(RotationRefusal::FamilyRevoked));
    let trail: Vec<(AuditKind, Option<String>, Option<u64>)> = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .map(|record| record.event)
        .filter(|event| matches!(event.kind, AuditKind::ConsentRevoked | AuditKind::Cascade))
        .map(|event| {
            assert_eq!(event.user.as_ref(), Some(&user));
            assert_eq!(event.client_id, Some(portal()));
            (event.kind, event.reason, event.families)
        })
        .collect();
    assert_eq!(
        trail,
        [
            (AuditKind::ConsentRevoked, Some("user".to_owned()), None),
            (
                AuditKind::Cascade,
                Some("consent_revoked".to_owned()),
                Some(1)
            ),
        ]
    );
    let again = call(
        &server,
        "POST",
        "grants/revoke",
        Some(&session),
        Some(json!({ "client_id": "portal" })),
    )
    .await;
    assert_eq!(again.body["revoked"], false, "nothing stands to end");
    assert_eq!(again.body["families"], 0);
}
