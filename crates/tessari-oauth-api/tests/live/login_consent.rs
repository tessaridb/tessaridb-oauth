//! The consent step over a live store: the page is told only what the user has not yet granted, allowing records the
//! grant before any code exists and answers where the browser goes with one, denying grants nothing and answers
//! `access_denied`, and nothing is answered without a session or for a request that is gone.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_core::consents::{ConsentRequest, Coverage};
use tessari_oauth_storage::consents::NewGrant;
use tessari_oauth_types::{Challenge, ClientId, Resource, ScopeSet, Timestamp, UserId};
use tower::ServiceExt;

use crate::authorize_resume::{VERIFIER, signed_in};
use crate::login::refused;
use crate::routes::{Answer, answer};
use crate::token_fixture::{
    API, BROWSER_COOKIE, NOW, REDIRECT, Server, browser, issuer, plenty, server, state, tenant,
    uncached,
};

const SESSION_COOKIE: &str = "__Host-tessari-session";
const CONSENT: &str = "/acme/login/api/consent";

/// Send `method` to `path` on the public router with `body` as JSON, carrying the session cookie `session`.
async fn call(
    server: &Server,
    method: &str,
    path: &str,
    session: Option<&str>,
    body: Option<String>,
) -> Answer {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 50_000))));
    request = match session {
        Some(value) => request.header(
            "cookie",
            format!("theme=dark; {BROWSER_COOKIE}; {SESSION_COOKIE}={value}"),
        ),
        None => request.header("cookie", BROWSER_COOKIE),
    };
    let body = body.map_or_else(Body::empty, Body::from);
    let response = public_router(state(server, plenty()))
        .oneshot(request.body(body).expect("a request"))
        .await
        .expect("the router answers");
    let answered = answer(response).await;
    uncached(&answered);
    answered
}

/// What the consent page is told about `interaction`.
async fn asked(server: &Server, interaction: &str, session: Option<&str>) -> Answer {
    let path = format!("{CONSENT}?interaction={interaction}");
    call(server, "GET", &path, session, None).await
}

/// The user's `decision` on `interaction`.
async fn decide(
    server: &Server,
    interaction: &str,
    session: Option<&str>,
    decision: &str,
) -> Answer {
    let body = json!({ "interaction": interaction, "decision": decision }).to_string();
    call(server, "POST", CONSENT, session, Some(body)).await
}

/// A pending authorization for `portal` asking `scopes` at the API, carrying `client_state` when given.
async fn pending(server: &Server, scopes: &str, client_state: Option<&str>) -> String {
    let request = AuthorizationRequest {
        client_id: ClientId::parse("portal").expect("a client id"),
        redirect_uri: REDIRECT.to_owned(),
        scopes: ScopeSet::parse(scopes).expect("scopes"),
        challenge: Challenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .expect("a challenge"),
        state: client_state.map(str::to_owned),
        resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
        nonce: None,
        silent: false,
        max_age: None,
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

/// Whether `interaction` is still waiting.
async fn waiting(server: &Server, interaction: &str) -> bool {
    server
        .storage
        .interactions
        .find(
            &tenant("acme"),
            interaction,
            &browser(),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .is_some()
}

/// What `scopes` at the API amount to against `user`'s grant to `portal`.
fn asking(scopes: &str) -> ConsentRequest {
    ConsentRequest {
        scopes: ScopeSet::parse(scopes).expect("scopes"),
        resources: BTreeSet::from([Resource::parse(API).expect("a resource")]),
    }
}

/// Whether `user`'s grant to `portal` covers `scopes` at the API.
async fn coverage(server: &Server, user: &UserId, scopes: &str) -> Coverage {
    server
        .storage
        .consents
        .check(
            &tenant("acme"),
            user,
            &ClientId::parse("portal").expect("a client id"),
            &asking(scopes),
            1,
        )
        .await
        .expect("the store answers")
}

/// How many `consented` records the trail holds for `user`.
async fn consented(server: &Server, user: &UserId) -> usize {
    server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail")
        .into_iter()
        .filter(|record| {
            record.event.kind.as_str() == "consented" && record.event.user.as_ref() == Some(user)
        })
        .count()
}

/// The query of the address a decision sends the browser on, which must be the client's redirect URI.
fn sent_to(answered: &Answer) -> Vec<(String, String)> {
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    let target = url::Url::parse(answered.body["redirect"].as_str().expect("a redirect"))
        .expect("an absolute address");
    assert_eq!(
        format!(
            "{}://{}{}",
            target.scheme(),
            target.host_str().expect("a host"),
            target.path()
        ),
        REDIRECT
    );
    target.query_pairs().into_owned().collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_page_is_told_only_what_is_not_yet_granted() {
    let server = server(2).await;
    let (_, session, user) = signed_in(&server, "lamarr@example.com").await;
    let interaction = pending(&server, "api:read api:write", None).await;
    let answered = asked(&server, &interaction, Some(&session)).await;
    assert_eq!(answered.status, StatusCode::OK, "{}", answered.body);
    assert_eq!(
        answered.body,
        json!({ "client_id": "portal", "scopes": ["api:read", "api:write"], "resources": [API] })
    );
    server
        .storage
        .consents
        .grant(&NewGrant {
            tenant: tenant("acme"),
            user: user.clone(),
            client_id: ClientId::parse("portal").expect("a client id"),
            request: asking("api:read"),
            policy_version: 1,
            shown_version: "1".to_owned(),
            at: Timestamp::from_unix_secs(NOW),
        })
        .await
        .expect("granted");
    let answered = asked(&server, &interaction, Some(&session)).await;
    assert_eq!(
        answered.body,
        json!({ "client_id": "portal", "scopes": ["api:write"], "resources": [] }),
        "only the delta"
    );
    server
        .storage
        .consents
        .grant(&NewGrant {
            tenant: tenant("acme"),
            user,
            client_id: ClientId::parse("portal").expect("a client id"),
            request: asking("api:write"),
            policy_version: 1,
            shown_version: "1".to_owned(),
            at: Timestamp::from_unix_secs(NOW),
        })
        .await
        .expect("granted");
    let answered = asked(&server, &interaction, Some(&session)).await;
    assert_eq!(
        answered.body,
        json!({ "client_id": "portal", "scopes": [], "resources": [] }),
        "nothing left to ask"
    );
    assert!(waiting(&server, &interaction).await, "asking takes nothing");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn allowing_records_the_grant_and_answers_a_code_the_client_redeems() {
    let server = server(2).await;
    let (interaction, session, user) = signed_in(&server, "franklin@example.com").await;
    assert!(matches!(
        coverage(&server, &user, "api:read").await,
        Coverage::Prompt { .. }
    ));
    let answered = decide(&server, &interaction, Some(&session), "allow").await;
    let pairs = sent_to(&answered);
    let names: Vec<&str> = pairs.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["code", "iss"], "no state was asked for");
    assert_eq!(pairs[1].1, issuer("acme"));
    let redeemed = crate::token_fixture::post(
        &server,
        "acme",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "portal"),
            ("code", &pairs[0].1),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{}", redeemed.body);
    assert_eq!(
        coverage(&server, &user, "api:read").await,
        Coverage::Covered
    );
    assert_eq!(consented(&server, &user).await, 1, "recorded once");
    let again = decide(&server, &interaction, Some(&session), "allow").await;
    refused(&again, StatusCode::GONE, "signin_expired", "answered once");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn denying_grants_nothing_and_answers_access_denied() {
    let server = server(2).await;
    let (_, session, user) = signed_in(&server, "goodall@example.com").await;
    let interaction = pending(&server, "api:read", Some("af0ifjsldkj")).await;
    let answered = decide(&server, &interaction, Some(&session), "deny").await;
    assert_eq!(
        sent_to(&answered),
        [
            ("error".to_owned(), "access_denied".to_owned()),
            ("state".to_owned(), "af0ifjsldkj".to_owned()),
            ("iss".to_owned(), issuer("acme")),
        ]
    );
    assert!(
        !waiting(&server, &interaction).await,
        "the request is answered"
    );
    let records = server
        .storage
        .consents
        .list(&tenant("acme"), &user)
        .await
        .expect("the store answers");
    assert!(records.is_empty(), "no record written");
    assert_eq!(consented(&server, &user).await, 0);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn without_a_session_nothing_is_answered() {
    let server = server(2).await;
    let interaction = pending(&server, "api:read", None).await;
    for (session, case) in [
        (None, "no cookie"),
        (Some("not-a-session"), "an unknown one"),
    ] {
        let answered = asked(&server, &interaction, session).await;
        refused(
            &answered,
            StatusCode::UNAUTHORIZED,
            "session_required",
            case,
        );
        let answered = decide(&server, &interaction, session, "allow").await;
        refused(
            &answered,
            StatusCode::UNAUTHORIZED,
            "session_required",
            case,
        );
    }
    assert!(waiting(&server, &interaction).await, "still pending");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_unreadable_or_gone_request_is_refused() {
    let server = server(2).await;
    let (_, session, _) = signed_in(&server, "meitner@example.com").await;
    let interaction = pending(&server, "api:read", None).await;
    let malformed = asked(&server, "not%2Fan%20id", Some(&session)).await;
    refused(
        &malformed,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "a malformed id",
    );
    let gone = asked(&server, "never-kept", Some(&session)).await;
    refused(
        &gone,
        StatusCode::GONE,
        "signin_expired",
        "a request that is gone",
    );
    let gone = decide(&server, "never-kept", Some(&session), "deny").await;
    refused(
        &gone,
        StatusCode::GONE,
        "signin_expired",
        "a decision on nothing",
    );
    let unknown = decide(&server, &interaction, Some(&session), "maybe").await;
    refused(
        &unknown,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "neither allow nor deny",
    );
    let empty = call(&server, "POST", CONSENT, Some(&session), None).await;
    refused(
        &empty,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "no body",
    );
    assert!(waiting(&server, &interaction).await, "nothing taken");
}
