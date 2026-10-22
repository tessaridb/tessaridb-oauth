//! The sign-in steps over a live store: `begin` binds a sign-in to a cookie only for a pending authorization, and
//! `identify` moves it on for any address with one answer, refusing a browser with no sign-in, a step out of order
//! and a body it cannot read. Every answer is protected, uncached and counted under its own limit.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_core::ceremony::Identity;
use tessari_oauth_storage::signins::Signin;
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_storage::users::Registered;
use tessari_oauth_types::{
    Challenge, ClientId, EmailAddress, Resource, ScopeSet, SigninBinding, Timestamp, UserId,
};
use tower::ServiceExt;

use crate::routes::{Answer, answer, header, protected};
use crate::token_fixture::{
    API, BROWSER_COOKIE, NOW, REDIRECT, Server, browser, passwords, plenty, server, state, tenant,
    uncached,
};

pub(crate) const KNOWN: &str = "ada@example.com";
const COOKIE: &str = "__Host-tessari-login";

/// POST `body` to `step` of `acme`'s sign-in under `limit` from `peer`, carrying `cookie` when given.
pub(crate) async fn post_from(
    server: &Server,
    limit: Limit,
    peer: SocketAddr,
    step: &str,
    cookie: Option<&str>,
    body: String,
) -> Answer {
    let mut public = state(server, plenty());
    public.login_limit = limit;
    let mut request = Request::post(format!("/acme/login/api/{step}"))
        .header("content-type", "application/json")
        .extension(ConnectInfo(peer));
    request = match cookie {
        Some(value) => request.header(
            "cookie",
            format!("theme=dark; {BROWSER_COOKIE}; {COOKIE}={value}"),
        ),
        None => request.header("cookie", BROWSER_COOKIE),
    };
    let response = public_router(public)
        .oneshot(request.body(Body::from(body)).expect("a request"))
        .await
        .expect("the router answers");
    let answered = answer(response).await;
    protected(&answered);
    uncached(&answered);
    answered
}

/// POST `body` to `step` under `limit` from one fixed address.
async fn post_limited(
    server: &Server,
    limit: Limit,
    step: &str,
    cookie: Option<&str>,
    body: String,
) -> Answer {
    let peer = SocketAddr::from(([192, 0, 2, 1], 50_000));
    post_from(server, limit, peer, step, cookie, body).await
}

pub(crate) async fn post(
    server: &Server,
    step: &str,
    cookie: Option<&str>,
    body: serde_json::Value,
) -> Answer {
    post_limited(server, plenty(), step, cookie, body.to_string()).await
}

/// A pending authorization for `portal` in `acme`, kept and ready to sign in.
async fn pending(server: &Server) -> String {
    let request = AuthorizationRequest {
        client_id: ClientId::parse("portal").expect("a client id"),
        redirect_uri: REDIRECT.to_owned(),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        challenge: Challenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .expect("a challenge"),
        state: None,
        resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
        nonce: None,
        silent: false,
    };
    server
        .storage
        .interactions
        .open(
            &tenant("acme"),
            &request,
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("kept")
}

/// The sign-in cookie value `begun` set.
fn cookie_value(begun: &Answer) -> String {
    let set = header(begun, "set-cookie");
    let (pair, _) = set.split_once(';').expect("attributes follow the value");
    let (name, value) = pair.split_once('=').expect("a name and a value");
    assert_eq!(name, COOKIE);
    value.to_owned()
}

/// Begin a sign-in for a fresh pending authorization and return its cookie value.
pub(crate) async fn begun(server: &Server) -> String {
    let interaction = pending(server).await;
    let answered = post(server, "begin", None, json!({ "interaction": interaction })).await;
    assert_eq!(answered.status, StatusCode::OK);
    cookie_value(&answered)
}

/// Where the sign-in under `cookie` stands, read straight from the store.
async fn identity(server: &Server, cookie: &str) -> Option<Identity> {
    signin(server, cookie).await.ceremony.identity().cloned()
}

/// The sign-in under `cookie`, read straight from the store.
pub(crate) async fn signin(server: &Server, cookie: &str) -> Signin {
    server
        .storage
        .signins
        .resume(
            &tenant("acme"),
            &SigninBinding::from_secret(cookie),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .expect("the sign-in is there")
}

pub(crate) async fn register(server: &Server, email: &str) -> UserId {
    let registered = server
        .storage
        .users
        .register(
            &tenant("acme"),
            &EmailAddress::parse(email).expect("an address"),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("registered");
    let Registered::Created(user) = registered else {
        panic!("a fresh address");
    };
    user
}

pub(crate) fn refused(answered: &Answer, status: StatusCode, code: &str, case: &str) {
    assert_eq!(answered.status, status, "{case}");
    assert_eq!(answered.body["code"], code, "{case}");
    assert!(
        answered.headers.get("set-cookie").is_none(),
        "{case}: no cookie set"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn begin_starts_nothing_without_a_pending_authorization() {
    let server = server(2).await;
    for (interaction, case) in [("never-kept", "unknown"), ("not/an id", "malformed")] {
        let answered = post(
            &server,
            "begin",
            None,
            json!({ "interaction": interaction }),
        )
        .await;
        refused(&answered, StatusCode::GONE, "signin_expired", case);
    }
    let answered = post_limited(&server, plenty(), "begin", None, "interaction=x".to_owned()).await;
    refused(
        &answered,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "not JSON",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn begin_binds_a_new_sign_in_to_a_fresh_cookie() {
    let server = server(2).await;
    let interaction = pending(&server).await;
    let first = post(
        &server,
        "begin",
        None,
        json!({ "interaction": interaction }),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body, json!({ "next": "identify" }));
    let set = header(&first, "set-cookie");
    assert!(
        set.ends_with("; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600"),
        "every attribute: {set}"
    );
    let value = cookie_value(&first);
    assert_eq!(value.len(), 43, "256 bits, base64url");
    let again = post(
        &server,
        "begin",
        None,
        json!({ "interaction": interaction }),
    )
    .await;
    assert_ne!(cookie_value(&again), value, "each begin draws its own");
    let signin = server
        .storage
        .signins
        .resume(
            &tenant("acme"),
            &SigninBinding::from_secret(value),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .expect("bound to the cookie");
    assert_eq!(signin.interaction, interaction);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_step_from_a_browser_with_no_sign_in_is_refused() {
    let server = server(2).await;
    let body = json!({ "email": KNOWN });
    for (cookie, case) in [
        (None, "no cookie"),
        (
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "a value this server never set",
        ),
        (Some("not a value"), "malformed"),
    ] {
        let answered = post(&server, "identify", cookie, body.clone()).await;
        refused(&answered, StatusCode::GONE, "signin_expired", case);
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn identify_answers_a_known_and_an_unknown_address_alike() {
    let server = server(2).await;
    let user = register(&server, KNOWN).await;
    let enrolled = register(&server, "grace@example.com").await;
    server
        .storage
        .factors
        .enroll_totp(
            &tenant("acme"),
            &server.kek,
            &enrolled,
            &[7; 20],
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("enrolled");
    let mut answers = Vec::new();
    for (email, expected) in [
        (
            KNOWN,
            Identity::Known {
                user,
                second_factor: false,
            },
        ),
        (
            "grace@example.com",
            Identity::Known {
                user: enrolled,
                second_factor: true,
            },
        ),
        ("nobody@example.com", Identity::Unknown),
    ] {
        let cookie = begun(&server).await;
        let answered = post(
            &server,
            "identify",
            Some(&cookie),
            json!({ "email": email }),
        )
        .await;
        let kept = signin(&server, &cookie).await;
        assert_eq!(kept.ceremony.identity().cloned(), Some(expected), "{email}");
        assert_eq!(
            kept.account,
            Some(passwords().signin_keys().account("acme", email)),
            "{email}: counted under the identified address's key, which names no address"
        );
        answers.push((answered.status, answered.body));
    }
    assert!(
        answers
            .iter()
            .all(|seen| *seen == (StatusCode::OK, json!({ "next": "first_factor" }))),
        "one answer for every address: {answers:?}"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn identify_twice_or_unreadable_is_refused() {
    let server = server(2).await;
    let cookie = begun(&server).await;
    let first = post(
        &server,
        "identify",
        Some(&cookie),
        json!({ "email": KNOWN }),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    let again = post(
        &server,
        "identify",
        Some(&cookie),
        json!({ "email": "other@example.com" }),
    )
    .await;
    refused(
        &again,
        StatusCode::CONFLICT,
        "step_refused",
        "identified twice",
    );
    assert_eq!(
        identity(&server, &cookie).await,
        Some(Identity::Unknown),
        "the first identity stands"
    );
    let fresh = begun(&server).await;
    let malformed = post(
        &server,
        "identify",
        Some(&fresh),
        json!({ "email": "not an address" }),
    )
    .await;
    refused(
        &malformed,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "malformed address",
    );
    assert_eq!(identity(&server, &fresh).await, None, "nothing moved");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_steps_are_counted_under_their_own_limit() {
    let server = server(2).await;
    let one = Limit {
        requests: NonZeroU64::MIN,
        window_secs: NonZeroU64::new(60).expect("non-zero"),
    };
    let body = json!({ "interaction": "never-kept" }).to_string();
    let first = post_limited(&server, one, "begin", None, body.clone()).await;
    assert_eq!(header(&first, "x-ratelimit-class"), "login");
    let second = post_limited(&server, one, "begin", None, body).await;
    refused(
        &second,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        "over the limit",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_steps_on_one_sign_in_let_exactly_one_through() {
    let server = Arc::new(server(16).await);
    let cookie = begun(&server).await;
    let mut racers = tokio::task::JoinSet::new();
    for turn in 0..64_u8 {
        let (server, cookie) = (Arc::clone(&server), cookie.clone());
        racers.spawn(async move {
            // Each from its own address, so the request counter does not queue them before the step.
            let peer = SocketAddr::from(([192, 0, 2, turn], 50_000));
            let body = json!({ "email": format!("racer-{turn}@example.com") }).to_string();
            post_from(&server, plenty(), peer, "identify", Some(&cookie), body).await
        });
    }
    let answers = racers.join_all().await;
    let statuses: Vec<StatusCode> = answers.iter().map(|answered| answered.status).collect();
    let passed = statuses
        .iter()
        .filter(|status| **status == StatusCode::OK)
        .count();
    assert_eq!(passed, 1, "{statuses:?}");
    for answered in answers
        .iter()
        .filter(|answered| answered.status != StatusCode::OK)
    {
        assert_eq!(answered.status, StatusCode::CONFLICT);
        assert_eq!(answered.body["code"], "step_refused");
    }
}
