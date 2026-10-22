//! A console session answers for its operator only while the issuer session it came from is alive and the operator
//! still holds a grant; anything else ends it. Signing out ends it too, and only a request from the console's own
//! origin may do that.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::operators::{OperatorGrant, OperatorRole};
use tessari_oauth_types::{SessionSecret, Timestamp, UserId};
use tower::ServiceExt;

use crate::admin_signin::console_state;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, Server, server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const OPERATOR: &str = "operator-9";

/// An operator holding `users` and `audit`, signed in at the issuer under `issuer_secret` and at the console under
/// `console_secret`, the console session naming the issuer session.
async fn signed_in(server: &Server, issuer_secret: &str, console_secret: &str) -> AdminState {
    signed_in_as(
        server,
        OPERATOR,
        &[OperatorRole::Users, OperatorRole::Audit],
        issuer_secret,
        console_secret,
    )
    .await
}

/// `operator` holding `roles` at `acme`, signed in at the issuer under `issuer_secret` and at the console under
/// `console_secret`.
pub(crate) async fn signed_in_as(
    server: &Server,
    operator: &str,
    roles: &[OperatorRole],
    issuer_secret: &str,
    console_secret: &str,
) -> AdminState {
    signed_in_at(
        server,
        "acme",
        operator,
        roles,
        issuer_secret,
        console_secret,
    )
    .await
}

/// `operator` holding `roles` at `company`, signed in at its issuer under `issuer_secret` and at its console under
/// `console_secret`.
pub(crate) async fn signed_in_at(
    server: &Server,
    company: &str,
    operator: &str,
    roles: &[OperatorRole],
    issuer_secret: &str,
    console_secret: &str,
) -> AdminState {
    let now = Timestamp::from_unix_secs(NOW);
    let home = tenant(company);
    let user = UserId::parse(operator).expect("a user id");
    for role in roles.iter().copied() {
        server
            .storage
            .operators
            .grant(
                &home,
                &OperatorGrant {
                    user: user.clone(),
                    role,
                    granted_by: "operator-1".to_owned(),
                    granted_at: now,
                    reason: "support rota".to_owned(),
                    expires_at: None,
                },
            )
            .await
            .expect("granted");
    }
    let methods = [Method::Password, Method::Totp];
    let issuer_secret = SessionSecret::from_secret(issuer_secret);
    server
        .storage
        .sessions
        .create(&home, &issuer_secret, &user, &methods, now)
        .await
        .expect("an issuer session");
    let sid = server
        .storage
        .sessions
        .find(&home, &issuer_secret, now)
        .await
        .expect("an answer")
        .expect("the issuer session")
        .sid;
    server
        .storage
        .admin
        .open(
            &home,
            &SessionSecret::from_secret(console_secret),
            &user,
            &sid,
            &methods,
            now,
        )
        .await
        .expect("a console session");
    console_state(server, CONSOLE)
}

async fn me(state: AdminState, console_secret: Option<&str>) -> Answer {
    let mut request = Request::get("/admin/acme/api/me");
    if let Some(secret) = console_secret {
        request = request.header(header::COOKIE, format!("__Host-tessari-admin={secret}"));
    }
    answer(
        admin_router(state)
            .oneshot(request.body(Body::empty()).expect("a request"))
            .await
            .expect("an answer"),
    )
    .await
}

async fn sign_out(state: AdminState, console_secret: &str, origin: Option<&str>) -> Answer {
    let mut request = Request::post("/admin/acme/signout").header(
        header::COOKIE,
        format!("__Host-tessari-admin={console_secret}"),
    );
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    answer(
        admin_router(state)
            .oneshot(request.body(Body::empty()).expect("a request"))
            .await
            .expect("an answer"),
    )
    .await
}

async fn console_session_exists(server: &Server, console_secret: &str) -> bool {
    server
        .storage
        .admin
        .find(
            &tenant("acme"),
            &SessionSecret::from_secret(console_secret),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("an answer")
        .is_some()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_console_names_its_operator_and_their_roles() {
    let server = server(2).await;
    let state = signed_in(&server, "issuer-secret-1", "console-secret-1").await;
    let named = me(state.clone(), Some("console-secret-1")).await;
    assert_eq!(named.status, StatusCode::OK);
    assert_eq!(named.body["user"], OPERATOR);
    let mut roles: Vec<&str> = named.body["roles"]
        .as_array()
        .expect("roles")
        .iter()
        .map(|role| role.as_str().expect("a role name"))
        .collect();
    roles.sort_unstable();
    assert_eq!(roles, ["audit", "users"]);
    let nobody = me(state, None).await;
    assert_eq!(nobody.status, StatusCode::UNAUTHORIZED);
    assert_eq!(nobody.body["code"], "session_required");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_console_session_ends_with_its_issuer_session_and_with_the_last_grant() {
    let server = server(2).await;
    let state = signed_in(&server, "issuer-secret-2", "console-secret-2").await;
    server
        .storage
        .sessions
        .end(
            &tenant("acme"),
            &SessionSecret::from_secret("issuer-secret-2"),
        )
        .await
        .expect("ended");
    let after_logout = me(state.clone(), Some("console-secret-2")).await;
    assert_eq!(after_logout.status, StatusCode::UNAUTHORIZED);
    assert!(!console_session_exists(&server, "console-secret-2").await);

    let state = signed_in(&server, "issuer-secret-3", "console-secret-3").await;
    let user = UserId::parse(OPERATOR).expect("a user id");
    for role in [OperatorRole::Users, OperatorRole::Audit] {
        server
            .storage
            .operators
            .revoke(
                &tenant("acme"),
                &user,
                role,
                "operator-1",
                "rota ended",
                Timestamp::from_unix_secs(NOW),
            )
            .await
            .expect("revoked");
    }
    let after_revoke = me(state, Some("console-secret-3")).await;
    assert_eq!(after_revoke.status, StatusCode::UNAUTHORIZED);
    assert!(!console_session_exists(&server, "console-secret-3").await);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn only_the_console_origin_signs_out() {
    let server = server(2).await;
    let state = signed_in(&server, "issuer-secret-4", "console-secret-4").await;
    for origin in [None, Some("https://evil.example.com")] {
        let refused = sign_out(state.clone(), "console-secret-4", origin).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert_eq!(refused.body["code"], "cross_origin", "{origin:?}");
        assert!(console_session_exists(&server, "console-secret-4").await);
    }
    let out = sign_out(state.clone(), "console-secret-4", Some(CONSOLE)).await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    let cleared = out.headers[header::SET_COOKIE].to_str().expect("a cookie");
    assert!(
        cleared.starts_with("__Host-tessari-admin=;") && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
    assert!(!console_session_exists(&server, "console-secret-4").await);
    let again = sign_out(state, "console-secret-4", Some(CONSOLE)).await;
    assert_eq!(
        again.status,
        StatusCode::NO_CONTENT,
        "signing out twice is no error"
    );
}
