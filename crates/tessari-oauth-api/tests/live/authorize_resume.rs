//! The authorization a finished sign-in continues, over a live store: with a session and the user's consent covering
//! the request it is answered once with a code the client redeems, without consent the browser is sent to be asked,
//! without a session it is sent to sign in, and a request that is gone is refused at the server, never redirected.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::codes::CodeAuthentication;
use tessari_oauth_core::consents::ConsentRequest;
use tessari_oauth_storage::codes::Consumed;
use tessari_oauth_storage::consents::NewGrant;
use tessari_oauth_types::{
    AuthorizationCode, ClientId, Resource, ScopeSet, SessionSecret, Timestamp, UserId,
};
use tower::ServiceExt;

use crate::login::{post, signin};
use crate::login_complete::session_value;
use crate::login_password::{RIGHT, identified, with_password};
use crate::routes::{Answer, header};
use crate::token_fixture::{
    API, BROWSER_COOKIE, NOW, REDIRECT, Server, browser, issuer, plenty, server, state, tenant,
};

/// The verifier whose S256 challenge the pending authorizations carry (RFC 7636 appendix B).
pub(crate) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const SESSION_COOKIE: &str = "__Host-tessari-session";

/// GET `path` on the public router, carrying the session cookie `session` when given.
async fn get(server: &Server, path: &str, session: Option<&str>) -> Answer {
    let mut request =
        Request::get(path).extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 50_000))));
    request = match session {
        Some(value) => request.header(
            "cookie",
            format!("theme=dark; {BROWSER_COOKIE}; {SESSION_COOKIE}={value}"),
        ),
        None => request.header("cookie", BROWSER_COOKIE),
    };
    let response = public_router(state(server, plenty()))
        .oneshot(request.body(Body::empty()).expect("a request"))
        .await
        .expect("the router answers");
    // A refusal here is an HTML page and a redirect has no body: the status and the headers are the answer.
    Answer {
        status: response.status(),
        headers: response.headers().clone(),
        body: serde_json::Value::Null,
    }
}

/// Sign `email` in with a password; answer the pending authorization's id, the session value and the user.
pub(crate) async fn signed_in(server: &Server, email: &str) -> (String, String, UserId) {
    let user = with_password(server, email).await;
    let cookie = identified(server, email).await;
    let interaction = signin(server, &cookie).await.interaction;
    let answered = post(
        server,
        "password",
        Some(&cookie),
        json!({ "password": RIGHT }),
    )
    .await;
    assert_eq!(answered.body["next"], "complete");
    (interaction, session_value(&answered), user)
}

/// Record `user`'s consent to the pending authorizations' scopes and resource for `portal`.
async fn consented(server: &Server, user: &UserId) {
    server
        .storage
        .consents
        .grant(&NewGrant {
            tenant: tenant("acme"),
            user: user.clone(),
            client_id: ClientId::parse("portal").expect("a client id"),
            request: ConsentRequest {
                scopes: ScopeSet::parse("api:read").expect("scopes"),
                resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
            },
            policy_version: 1,
            shown_version: "1".to_owned(),
            at: Timestamp::from_unix_secs(NOW),
        })
        .await
        .expect("granted");
}

fn resume_path(interaction: &str) -> String {
    format!("/acme/oauth2/authorize/resume?interaction={interaction}")
}

/// The query of the redirect `answered` sent the browser on.
fn sent_to(answered: &Answer) -> url::Url {
    assert_eq!(answered.status, StatusCode::SEE_OTHER);
    url::Url::parse(header(answered, "location")).expect("an absolute location")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_covered_request_is_answered_once_with_a_code_the_client_redeems() {
    let server = server(2).await;
    let (interaction, session, user) = signed_in(&server, "lovelace@example.com").await;
    consented(&server, &user).await;
    let answered = get(&server, &resume_path(&interaction), Some(&session)).await;
    let target = sent_to(&answered);
    assert_eq!(
        format!(
            "{}://{}{}",
            target.scheme(),
            target.host_str().expect("a host"),
            target.path()
        ),
        REDIRECT
    );
    let pairs: Vec<(String, String)> = target.query_pairs().into_owned().collect();
    let names: Vec<&str> = pairs.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["code", "iss"], "no state was asked for");
    assert_eq!(pairs[1].1, issuer("acme"));
    let code = pairs[0].1.clone();
    let redeemed = crate::token_fixture::post(
        &server,
        "acme",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "portal"),
            ("code", &code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{}", redeemed.body);
    assert!(redeemed.body["access_token"].is_string());
    let again = get(&server, &resume_path(&interaction), Some(&session)).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "answered once");
    assert!(again.headers.get("location").is_none(), "never redirected");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_consent_the_browser_is_sent_to_be_asked_and_the_request_waits() {
    let server = server(2).await;
    let (interaction, session, _) = signed_in(&server, "turing@example.com").await;
    let answered = get(&server, &resume_path(&interaction), Some(&session)).await;
    assert_eq!(
        sent_to(&answered).as_str(),
        format!("{}/consent?interaction={interaction}", issuer("acme"))
    );
    let waiting = server
        .storage
        .interactions
        .find(
            &tenant("acme"),
            &interaction,
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers");
    assert!(waiting.is_some(), "still pending");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_a_session_the_browser_is_sent_to_sign_in() {
    let server = server(2).await;
    let (interaction, _, user) = signed_in(&server, "hamilton@example.com").await;
    consented(&server, &user).await;
    for (session, case) in [
        (None, "no cookie"),
        (Some("not-a-session"), "an unknown one"),
    ] {
        let answered = get(&server, &resume_path(&interaction), session).await;
        assert_eq!(
            sent_to(&answered).as_str(),
            format!("{}/login?interaction={interaction}", issuer("acme")),
            "{case}"
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_that_is_gone_is_refused_at_the_server() {
    let server = server(2).await;
    let (_, session, _) = signed_in(&server, "noether@example.com").await;
    for path in [
        resume_path("never-kept"),
        resume_path("not%2Fan%20id"),
        "/acme/oauth2/authorize/resume".to_owned(),
    ] {
        let answered = get(&server, &path, Some(&session)).await;
        assert_eq!(answered.status, StatusCode::BAD_REQUEST, "{path}");
        assert!(answered.headers.get("location").is_none(), "{path}");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_answer_carries_the_state_the_client_sent() {
    let server = server(2).await;
    let (interaction, session, user) = signed_in(&server, "hopper2@example.com").await;
    consented(&server, &user).await;
    // A second pending authorization, with a state, continued under the same session.
    let mut request = server
        .storage
        .interactions
        .find(
            &tenant("acme"),
            &interaction,
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .expect("pending");
    request.state = Some("af0ifjsldkj".to_owned());
    let with_state = server
        .storage
        .interactions
        .open(
            &tenant("acme"),
            &request,
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("kept");
    let answered = get(&server, &resume_path(&with_state), Some(&session)).await;
    let state: Vec<String> = sent_to(&answered)
        .query_pairs()
        .filter(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .collect();
    assert_eq!(state, ["af0ifjsldkj"]);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_code_records_how_the_user_signed_in_and_the_nonce_the_client_sent() {
    let server = server(2).await;
    let (interaction, _, user) = signed_in(&server, "lovelace@example.com").await;
    consented(&server, &user).await;
    let now = Timestamp::from_unix_secs(NOW);
    // A session of the same user opened an hour earlier with two methods, so its facts differ from the moment the
    // code is issued and from a password-only sign-in.
    let session = "an-earlier-session-of-lovelace".to_owned();
    server
        .storage
        .sessions
        .create(
            &tenant("acme"),
            &SessionSecret::from_secret(session.clone()),
            &user,
            &[Method::Password, Method::Totp],
            Timestamp::from_unix_secs(NOW - 3_600),
        )
        .await
        .expect("opened");
    let mut request = server
        .storage
        .interactions
        .find(&tenant("acme"), &interaction, &browser(), now)
        .await
        .expect("the store answers")
        .expect("pending");
    request.nonce = Some("n-0S6_WzA2Mj".to_owned());
    let with_nonce = server
        .storage
        .interactions
        .open(&tenant("acme"), &request, &browser(), now)
        .await
        .expect("kept");
    let answered = get(&server, &resume_path(&with_nonce), Some(&session)).await;
    let code = sent_to(&answered)
        .query_pairs()
        .find(|(name, _)| name == "code")
        .map(|(_, value)| value.into_owned())
        .expect("a code");
    let opened = server
        .storage
        .sessions
        .find(&tenant("acme"), &SessionSecret::from_secret(session), now)
        .await
        .expect("the store answers")
        .expect("the session");
    let consumed = server
        .storage
        .codes
        .consume(&tenant("acme"), &AuthorizationCode::from_secret(code), now)
        .await
        .expect("the store answers");
    let Consumed::Fresh(issued) = consumed else {
        panic!("a fresh code");
    };
    assert_eq!(
        issued.authentication,
        CodeAuthentication {
            auth_time: Timestamp::from_unix_secs(NOW - 3_600),
            methods: vec![Method::Password, Method::Totp],
            sid: opened.sid,
        }
    );
    assert_eq!(issued.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
}
