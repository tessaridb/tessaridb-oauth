//! The authorization endpoint (RFC 6749 §4.1.1, OpenID Connect Core §3.1.2): a request that cannot be tied to a
//! redirect URI its client registered is refused on a page at the server and sent nowhere; a later refusal goes back
//! to that URI with `state` and the issuer (RFC 9207); a request asking for no page with no session cookie is refused
//! rather than shown one; a valid request is kept and the browser handed to sign-in with its id alone, or, when it
//! asked for no page and carries a session cookie, to be answered from that session. Every refusal is recorded.

use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroU64;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tessari_oauth_api::{PublicState, public_router};
use tessari_oauth_storage::audit::{AuditEvent, AuditKind};
use tessari_oauth_storage::throttle::Limit;
use tessari_oauth_types::{BrowserBinding, ClientId, Resource, Timestamp};
use tower::ServiceExt;

use crate::routes::{Answer, header};
use crate::token_fixture::{
    API, NOW, REDIRECT, Server, issuer, plenty, server, state, tenant, uncached,
};

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const STATE: &str = "af0ifjsldkj";
const ATTACKER: &str = "https://attacker.example.net/catch";

/// What the endpoint answered: the parts every answer is checked on, and the body as text.
struct Page {
    answer: Answer,
    text: String,
}

async fn send(public: PublicState, request: Request<Body>) -> Page {
    let response = public_router(public)
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    Page {
        answer: Answer {
            status,
            headers,
            body: serde_json::Value::Null,
        },
        text: String::from_utf8(bytes.to_vec()).expect("UTF-8"),
    }
}

fn encode(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// GET `acme`'s authorization endpoint with `pairs` as the query.
async fn query(server: &Server, pairs: &[(&str, &str)]) -> Page {
    let uri = format!("/acme/oauth2/authorize?{}", encode(pairs));
    send(
        state(server, plenty()),
        Request::get(uri).body(Body::empty()).expect("a request"),
    )
    .await
}

/// POST `body` as `content_type` to `acme`'s authorization endpoint.
async fn form(server: &Server, content_type: &str, body: String) -> Page {
    send(
        state(server, plenty()),
        Request::post("/acme/oauth2/authorize")
            .header("content-type", content_type)
            .body(Body::from(body))
            .expect("a request"),
    )
    .await
}

/// A request every check accepts, from `portal`.
fn valid() -> Vec<(&'static str, &'static str)> {
    vec![
        ("response_type", "code"),
        ("client_id", "portal"),
        ("redirect_uri", REDIRECT),
        ("scope", "api:read"),
        ("state", STATE),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]
}

fn with(name: &'static str, value: &'static str) -> Vec<(&'static str, &'static str)> {
    let mut pairs: Vec<_> = valid()
        .into_iter()
        .filter(|(key, _)| *key != name)
        .collect();
    pairs.push((name, value));
    pairs
}

/// The refusal was shown at the server and sent nowhere, naming nothing the request carried.
fn rendered(page: &Page, case: &str) {
    assert_eq!(page.answer.status, StatusCode::BAD_REQUEST, "{case}");
    assert!(
        page.answer.headers.get("location").is_none(),
        "{case}: not redirected"
    );
    assert_eq!(
        header(&page.answer, "content-type"),
        "text/html; charset=utf-8",
        "{case}"
    );
    assert!(
        page.text.contains("invalid_request"),
        "{case}: {}",
        page.text
    );
    for carried in [ATTACKER, STATE, CHALLENGE, "portal"] {
        assert!(
            !page.text.contains(carried),
            "{case}: the page names {carried}"
        );
    }
    uncached(&page.answer);
}

/// The refusal went back to the registered redirect URI as `error`, with `state` and the issuer.
fn redirected(page: &Page, error: &str, case: &str) {
    assert_eq!(page.answer.status, StatusCode::SEE_OTHER, "{case}");
    let location = url::Url::parse(header(&page.answer, "location")).expect("a URL");
    assert_eq!(
        &location[..url::Position::AfterPath],
        REDIRECT,
        "{case}: only to the registered URI"
    );
    let found: HashMap<String, String> = location.query_pairs().into_owned().collect();
    let expected = HashMap::from([
        ("error".to_owned(), error.to_owned()),
        ("state".to_owned(), STATE.to_owned()),
        ("iss".to_owned(), issuer("acme")),
    ]);
    assert_eq!(found, expected, "{case}");
    uncached(&page.answer);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_not_tied_to_a_registered_redirect_is_refused_at_the_server() {
    let server = server(2).await;
    rendered(
        &query(&server, &with("client_id", "nobody")).await,
        "an unknown client",
    );
    rendered(
        &query(&server, &with("redirect_uri", ATTACKER)).await,
        "an unregistered redirect URI",
    );
    let mut bad_scope_too = with("redirect_uri", ATTACKER);
    bad_scope_too.retain(|(key, _)| *key != "scope");
    bad_scope_too.push(("scope", "admin"));
    rendered(
        &query(&server, &bad_scope_too).await,
        "a later fault does not make an unregistered URI redirectable",
    );
    let mut twice = valid();
    twice.push(("client_id", "kiosk"));
    rendered(&query(&server, &twice).await, "a repeated parameter");
    rendered(
        &form(&server, "application/json", "{}".to_owned()).await,
        "a body that is not a form",
    );
    rendered(
        &form(
            &server,
            "application/x-www-form-urlencoded",
            format!("{}&pad={}", encode(&valid()), "a".repeat(17 * 1024)),
        )
        .await,
        "a form larger than the endpoint reads",
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_later_refusal_returns_to_the_client_with_state_and_issuer() {
    let server = server(2).await;
    for (pairs, error, case) in [
        (
            with("response_type", "token"),
            "unsupported_response_type",
            "an implicit request",
        ),
        (
            with("scope", "api:admin"),
            "invalid_scope",
            "a scope beyond the ceiling",
        ),
        (
            with("code_challenge_method", "plain"),
            "invalid_request",
            "a plain challenge",
        ),
        (
            with("resource", "https://other.example.com/"),
            "invalid_target",
            "an unregistered resource",
        ),
        (
            with("prompt", "none login"),
            "invalid_request",
            "none combined",
        ),
        (
            with("prompt", "none"),
            "login_required",
            "no page and no session",
        ),
    ] {
        redirected(&query(&server, &pairs).await, error, case);
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_valid_request_is_kept_and_handed_to_sign_in_by_its_id_alone() {
    let server = server(2).await;
    let by_query = query(&server, &with("nonce", "n-0S6_WzA2Mj")).await;
    let by_form = form(
        &server,
        "application/x-www-form-urlencoded",
        encode(&with("nonce", "n-0S6_WzA2Mj")),
    )
    .await;
    let mut ids = BTreeSet::new();
    for page in [by_query, by_form] {
        assert_eq!(page.answer.status, StatusCode::SEE_OTHER);
        uncached(&page.answer);
        let location = url::Url::parse(header(&page.answer, "location")).expect("a URL");
        assert_eq!(
            &location[..url::Position::AfterPath],
            format!("{}/login", issuer("acme"))
        );
        let pairs: Vec<(String, String)> = location.query_pairs().into_owned().collect();
        let [(name, id)] = pairs.as_slice() else {
            panic!("the interaction id alone travels: {pairs:?}");
        };
        assert_eq!(name, "interaction");
        let kept = server
            .storage
            .interactions
            .find(
                &tenant("acme"),
                id,
                &browser_set(&page.answer),
                Timestamp::from_unix_secs(NOW),
            )
            .await
            .expect("the store answers")
            .expect("the request was kept");
        assert_eq!(
            kept.client_id,
            ClientId::parse("portal").expect("a client id")
        );
        assert_eq!(kept.redirect_uri, REDIRECT);
        assert_eq!(kept.challenge.as_str(), CHALLENGE);
        assert_eq!(kept.state.as_deref(), Some(STATE));
        assert_eq!(kept.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
        assert_eq!(
            kept.resources,
            BTreeSet::from([Resource::parse(API).expect("a resource")])
        );
        ids.insert(id.clone());
    }
    assert_eq!(ids.len(), 2, "each request is kept on its own");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_that_asks_for_no_page_with_a_session_is_kept_and_sent_to_be_answered_from_it() {
    let server = server(2).await;
    let uri = format!("/acme/oauth2/authorize?{}", encode(&with("prompt", "none")));
    let page = send(
        state(&server, plenty()),
        Request::get(uri)
            .header(
                "cookie",
                "__Host-tessari-session=a-session-the-resume-step-looks-up",
            )
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(page.answer.status, StatusCode::SEE_OTHER);
    uncached(&page.answer);
    let location = url::Url::parse(header(&page.answer, "location")).expect("a URL");
    assert_eq!(
        &location[..url::Position::AfterPath],
        format!("{}/oauth2/authorize/resume", issuer("acme")),
        "no sign-in page: the session answers"
    );
    let pairs: Vec<(String, String)> = location.query_pairs().into_owned().collect();
    let [(name, id)] = pairs.as_slice() else {
        panic!("the interaction id alone travels: {pairs:?}");
    };
    assert_eq!(name, "interaction");
    let kept = server
        .storage
        .interactions
        .find(
            &tenant("acme"),
            id,
            &browser_set(&page.answer),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("the store answers")
        .expect("the request was kept");
    assert!(kept.silent, "kept as a request that asked for no page");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_refusal_is_recorded_with_its_client_and_reason() {
    let server = server(2).await;
    query(&server, &with("redirect_uri", ATTACKER)).await;
    query(&server, &with("prompt", "none")).await;
    query(&server, &valid()).await;
    let trail: Vec<AuditEvent> = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail reads")
        .into_iter()
        .map(|record| record.event)
        .collect();
    let refused = |reason: &str| AuditEvent {
        client_id: Some(ClientId::parse("portal").expect("a client id")),
        reason: Some(reason.to_owned()),
        ..AuditEvent::of(AuditKind::Refused)
    };
    assert_eq!(
        trail,
        [
            refused("UnregisteredRedirectUri"),
            refused("SilentWithoutSession")
        ],
        "two refusals, and nothing for the request that was kept"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_endpoint_is_counted_under_its_own_limit() {
    let server = server(2).await;
    let mut public = state(&server, plenty());
    public.authorize_limit = Limit {
        requests: NonZeroU64::MIN,
        window_secs: NonZeroU64::new(60).expect("non-zero"),
    };
    let request = || {
        Request::get(format!("/acme/oauth2/authorize?{}", encode(&valid())))
            .body(Body::empty())
            .expect("a request")
    };
    let first = send(public.clone(), request()).await;
    assert_eq!(first.answer.status, StatusCode::SEE_OTHER);
    assert_eq!(header(&first.answer, "x-ratelimit-class"), "authorize");
    assert_eq!(header(&first.answer, "x-ratelimit-limit"), "1");
    let second = send(public, request()).await;
    assert_eq!(second.answer.status, StatusCode::TOO_MANY_REQUESTS);
}

/// The browser the answer's browser cookie names, after checking the cookie is kept only as this issuer's own.
fn browser_set(answered: &Answer) -> BrowserBinding {
    let set = header(answered, "set-cookie");
    for attribute in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=600",
    ] {
        assert!(
            set.split("; ").any(|part| part == attribute),
            "{attribute} in {set}"
        );
    }
    let (pair, _) = set.split_once(';').expect("attributes follow the value");
    let value = pair
        .strip_prefix("__Host-tessari-browser=")
        .unwrap_or_else(|| panic!("the browser cookie is set: {set}"));
    assert_eq!(value.len(), 43, "256 bits, base64url");
    BrowserBinding::from_secret(value)
}
