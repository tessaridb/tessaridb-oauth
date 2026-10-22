//! RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0): a client sends the browser to the issuer with an ID
//! token it was issued; the issuer ends the session that browser holds only when the token names that very session,
//! and returns the browser only to a post-logout URI the client registered, carrying `state`. A request without a
//! readable hint, or naming another client, ends nothing and goes nowhere.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tessari_oauth_api::public_router;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::codes::{CodeAuthentication, IssuedCode};
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_types::{
    AuthorizationCode, Challenge, ClientId, Resource, ScopeSet, SessionSecret, Timestamp, UserId,
};
use tower::ServiceExt;

use crate::authorize_resume::{get, signed_in};
use crate::routes::{Answer, header};
use crate::token_fixture::{
    API, BROWSER_COOKIE, NOW, REDIRECT, SIGNED_OUT, Server, VERIFIER, plenty, post, redemption,
    server, state, tenant,
};

/// An ID token `tenant_name` issued to `client` for `user` in the session `sid`, by a code redeemed at its token
/// endpoint.
async fn id_token(
    server: &Server,
    tenant_name: &str,
    client: &str,
    user: &UserId,
    sid: &str,
) -> String {
    let secret = format!("code-{tenant_name}-{client}-{sid}");
    let issued = IssuedCode {
        tenant: tenant(tenant_name),
        client_id: ClientId::parse(client).expect("a client id"),
        user: user.clone(),
        redirect_uri: REDIRECT.to_owned(),
        challenge: Challenge::of(VERIFIER).expect("a challenge"),
        scopes: ScopeSet::parse("openid api:read").expect("scopes"),
        resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
        expires_at: Timestamp::from_unix_secs(NOW + 60),
        authentication: CodeAuthentication {
            auth_time: Timestamp::from_unix_secs(NOW - 60),
            methods: vec![Method::Password],
            sid: sid.to_owned(),
        },
        nonce: None,
    };
    server
        .storage
        .codes
        .issue(&AuthorizationCode::from_secret(&secret), &issued)
        .await
        .expect("issued");
    let answered = post(server, tenant_name, &redemption(client, &secret)).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    answered.body["id_token"]
        .as_str()
        .expect("an ID token")
        .to_owned()
}

/// The public id of the session under the cookie value `value`, when it is still alive.
async fn session_id(server: &Server, value: &str) -> Option<String> {
    server
        .storage
        .sessions
        .find(
            &tenant("acme"),
            &SessionSecret::from_secret(value.to_owned()),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .map(|session| session.sid)
}

/// A signed-in browser: its session cookie value, the session's public id and the user.
async fn browser(server: &Server, email: &str) -> (String, String, UserId) {
    let (_, session, user) = signed_in(server, email).await;
    let sid = session_id(server, &session).await.expect("a live session");
    (session, sid, user)
}

/// The logout path of `acme` with `pairs` as its query.
fn logout(pairs: &[(&str, &str)]) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    format!("/acme/oauth2/logout?{query}")
}

/// How many `SessionsEnded` records for `user` name the reason `rp_initiated`.
async fn recorded(server: &Server, user: &UserId) -> usize {
    server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .filter(|record| {
            record.event.kind == AuditKind::SessionsEnded
                && record.event.user.as_ref() == Some(user)
                && record.event.reason.as_deref() == Some("rp_initiated")
        })
        .count()
}

/// Whether `answer` is a page shown at the issuer: HTML, sent nowhere.
fn shown_here(answer: &Answer, status: StatusCode) {
    assert_eq!(answer.status, status);
    assert!(answer.headers.get("location").is_none(), "sent nowhere");
    assert!(header(answer, "content-type").starts_with("text/html"));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_hint_naming_the_browsers_session_ends_it_and_returns_to_the_registered_uri_with_state() {
    let server = server(2).await;
    let (session, sid, user) = browser(&server, "turing@example.com").await;
    let hint = id_token(&server, "acme", "portal", &user, &sid).await;
    let path = logout(&[
        ("id_token_hint", &hint),
        ("post_logout_redirect_uri", SIGNED_OUT),
        ("state", "s-42"),
    ]);
    let answered = get(&server, &path, Some(&session)).await;
    assert_eq!(answered.status, StatusCode::SEE_OTHER);
    assert_eq!(
        header(&answered, "location"),
        format!("{SIGNED_OUT}?state=s-42")
    );
    assert!(
        header(&answered, "set-cookie").contains("Max-Age=0"),
        "the session cookie is cleared"
    );
    assert_eq!(
        session_id(&server, &session).await,
        None,
        "the session is over"
    );
    assert_eq!(recorded(&server, &user).await, 1);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_hint_naming_another_session_ends_nothing_the_browser_holds() {
    let server = server(2).await;
    let (session, _, user) = browser(&server, "turing@example.com").await;
    let hint = id_token(
        &server,
        "acme",
        "portal",
        &user,
        "another-session-public-id",
    )
    .await;
    let path = logout(&[
        ("id_token_hint", &hint),
        ("post_logout_redirect_uri", SIGNED_OUT),
    ]);
    let answered = get(&server, &path, Some(&session)).await;
    assert_eq!(answered.status, StatusCode::SEE_OTHER);
    assert!(
        session_id(&server, &session).await.is_some(),
        "still signed in"
    );
    assert_eq!(recorded(&server, &user).await, 0);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_a_hint_nothing_is_ended_and_the_browser_goes_nowhere() {
    let server = server(2).await;
    let (session, _, user) = browser(&server, "turing@example.com").await;
    let path = logout(&[("post_logout_redirect_uri", SIGNED_OUT)]);
    let answered = get(&server, &path, Some(&session)).await;
    shown_here(&answered, StatusCode::BAD_REQUEST);
    assert!(
        session_id(&server, &session).await.is_some(),
        "still signed in"
    );
    assert_eq!(recorded(&server, &user).await, 0);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_hint_another_tenant_signed_is_refused_and_ends_nothing() {
    let server = server(2).await;
    let (session, sid, user) = browser(&server, "turing@example.com").await;
    let foreign = id_token(&server, "initech", "portal", &user, &sid).await;
    let path = logout(&[
        ("id_token_hint", &foreign),
        ("post_logout_redirect_uri", SIGNED_OUT),
    ]);
    let answered = get(&server, &path, Some(&session)).await;
    shown_here(&answered, StatusCode::BAD_REQUEST);
    assert!(
        session_id(&server, &session).await.is_some(),
        "still signed in"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_id_other_than_the_hints_audience_is_refused_and_ends_nothing() {
    let server = server(2).await;
    let (session, sid, user) = browser(&server, "turing@example.com").await;
    let hint = id_token(&server, "acme", "portal", &user, &sid).await;
    let path = logout(&[
        ("id_token_hint", &hint),
        ("client_id", "kiosk"),
        ("post_logout_redirect_uri", SIGNED_OUT),
    ]);
    let answered = get(&server, &path, Some(&session)).await;
    shown_here(&answered, StatusCode::BAD_REQUEST);
    assert!(
        session_id(&server, &session).await.is_some(),
        "still signed in"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_unregistered_post_logout_uri_ends_the_session_but_is_never_followed() {
    let server = server(2).await;
    let (session, sid, user) = browser(&server, "turing@example.com").await;
    let hint = id_token(&server, "acme", "portal", &user, &sid).await;
    for unregistered in [
        "https://evil.example.com/signed-out",
        "https://app.example.com/signed-out/more",
        REDIRECT,
    ] {
        let path = logout(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", unregistered),
        ]);
        let answered = get(&server, &path, Some(&session)).await;
        shown_here(&answered, StatusCode::OK);
    }
    assert_eq!(
        session_id(&server, &session).await,
        None,
        "the session is over"
    );
    assert_eq!(recorded(&server, &user).await, 1, "ended once");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_form_post_ends_the_session_as_a_get_does() {
    let server = server(2).await;
    let (session, sid, user) = browser(&server, "turing@example.com").await;
    let hint = id_token(&server, "acme", "portal", &user, &sid).await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([("id_token_hint", hint.as_str())])
        .finish();
    let request = Request::post("/acme/oauth2/logout")
        .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 50_000))))
        .header("content-type", "application/x-www-form-urlencoded")
        .header(
            "cookie",
            format!("{BROWSER_COOKIE}; __Host-tessari-session={session}"),
        )
        .body(Body::from(body))
        .expect("a request");
    let response = public_router(state(&server, plenty()))
        .oneshot(request)
        .await
        .expect("the router answers");
    assert_eq!(response.status(), StatusCode::OK, "the signed-out page");
    assert_eq!(
        session_id(&server, &session).await,
        None,
        "the session is over"
    );
}

/// The clients the session under the cookie value `value` was signed in to with an ID token.
async fn session_clients(server: &Server, value: &str) -> Vec<String> {
    server
        .storage
        .sessions
        .find(
            &tenant("acme"),
            &SessionSecret::from_secret(value.to_owned()),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .expect("a live session")
        .clients
        .iter()
        .map(|client| client.as_str().to_owned())
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_session_remembers_each_client_it_issued_an_id_token_to_and_no_other() {
    let server = server(2).await;
    let (session, sid, user) = browser(&server, "turing@example.com").await;
    assert!(session_clients(&server, &session).await.is_empty());
    let issued = IssuedCode {
        tenant: tenant("acme"),
        client_id: ClientId::parse("kiosk").expect("a client id"),
        user: user.clone(),
        redirect_uri: REDIRECT.to_owned(),
        challenge: Challenge::of(VERIFIER).expect("a challenge"),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
        expires_at: Timestamp::from_unix_secs(NOW + 60),
        authentication: CodeAuthentication {
            auth_time: Timestamp::from_unix_secs(NOW - 60),
            methods: vec![Method::Password],
            sid: sid.clone(),
        },
        nonce: None,
    };
    server
        .storage
        .codes
        .issue(
            &AuthorizationCode::from_secret("code-without-openid"),
            &issued,
        )
        .await
        .expect("issued");
    let answered = post(&server, "acme", &redemption("kiosk", "code-without-openid")).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    assert!(
        session_clients(&server, &session).await.is_empty(),
        "no ID token, nobody to tell"
    );
    id_token(&server, "acme", "portal", &user, &sid).await;
    assert_eq!(session_clients(&server, &session).await, vec!["portal"]);
}
