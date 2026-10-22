//! Coming back to the admin console: the sign-in its browser began is taken once, the `state` and `iss` it carries
//! back are compared, the code is spent and its bindings checked as the token endpoint checks them, its `nonce` must be
//! the one sent, and only an operator who signed in with two factors gets a session. Every refusal answers alike, opens
//! nothing and is audited.

use std::collections::{BTreeSet, HashMap};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::codes::{CodeAuthentication, IssuedCode};
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::{OperatorGrant, OperatorRole};
use tessari_oauth_types::{
    AuthorizationCode, Challenge, ClientId, Resource, ScopeSet, SessionSecret, SigninBinding,
    Timestamp, UserId,
};
use tower::ServiceExt;
use url::Url;

use crate::admin_signin::console_state;
use crate::routes::answer;
use crate::token_fixture::{NOW, Server, server, tenant};

const PUBLIC: &str = "https://id.example.com";
const CONSOLE: &str = "https://admin.example.com";
const ISSUER: &str = "https://id.example.com/acme";
const OPERATOR: &str = "operator-7";
const SID: &str = "c2Vzc2lvbi1hZG1pbg";

/// A sign-in begun at the console: the browser's cookie value and what the issuer was sent.
struct Begun {
    cookie: String,
    state: String,
    nonce: String,
    challenge: String,
}

async fn send(state: AdminState, path: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut request = Request::get(path);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    admin_router(state)
        .oneshot(request.body(Body::empty()).expect("a request"))
        .await
        .expect("an answer")
}

async fn begin(state: &AdminState) -> Begun {
    let answer = send(state.clone(), "/admin/acme/signin", None).await;
    assert_eq!(answer.status(), StatusCode::SEE_OTHER);
    let cookie = answer.headers()[header::SET_COOKIE]
        .to_str()
        .expect("a cookie")
        .split(';')
        .next()
        .expect("a pair")
        .to_owned();
    let location = Url::parse(
        answer.headers()[header::LOCATION]
            .to_str()
            .expect("a location"),
    )
    .expect("a URL");
    let query: HashMap<String, String> = location.query_pairs().into_owned().collect();
    Begun {
        cookie,
        state: query["state"].clone(),
        nonce: query["nonce"].clone(),
        challenge: query["code_challenge"].clone(),
    }
}

/// The company served, its console registered, and `operator-7` holding the `users` role.
async fn console(server: &Server) -> AdminState {
    let now = Timestamp::from_unix_secs(NOW);
    server
        .storage
        .provision_company(&tenant("acme"), PUBLIC, CONSOLE, now)
        .await
        .expect("provisioned");
    server
        .storage
        .operators
        .grant(
            &tenant("acme"),
            &OperatorGrant {
                user: UserId::parse(OPERATOR).expect("a user id"),
                role: OperatorRole::Users,
                granted_by: "operator-1".to_owned(),
                granted_at: now,
                reason: "support rota".to_owned(),
                expires_at: None,
            },
        )
        .await
        .expect("granted");
    console_state(server, CONSOLE)
}

/// The code `secret` the issuer gave `user` for the sign-in `begun`, after `methods`, carrying `nonce`.
async fn issue(
    server: &Server,
    secret: &str,
    begun: &Begun,
    user: &str,
    methods: Vec<Method>,
    nonce: &str,
) {
    let issued = IssuedCode {
        tenant: tenant("acme"),
        client_id: ClientId::parse("admin-console").expect("a client id"),
        user: UserId::parse(user).expect("a user id"),
        redirect_uri: format!("{CONSOLE}/admin/acme/callback"),
        challenge: Challenge::parse(begun.challenge.clone()).expect("a challenge"),
        scopes: ScopeSet::parse("openid").expect("scopes"),
        resources: BTreeSet::from([
            Resource::parse(format!("{PUBLIC}/acme/admin")).expect("a resource")
        ]),
        expires_at: Timestamp::from_unix_secs(NOW + 60),
        authentication: CodeAuthentication {
            auth_time: Timestamp::from_unix_secs(NOW),
            methods,
            sid: SID.to_owned(),
        },
        nonce: Some(nonce.to_owned()),
    };
    server
        .storage
        .codes
        .issue(&AuthorizationCode::from_secret(secret), &issued)
        .await
        .expect("issued");
}

fn callback(code: &str, state: &str, iss: &str) -> String {
    let mut url = Url::parse("https://admin.example.com/admin/acme/callback").expect("a URL");
    url.query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state)
        .append_pair("iss", iss);
    format!("{}?{}", url.path(), url.query().expect("a query"))
}

fn two_factors() -> Vec<Method> {
    vec![Method::Password, Method::Totp]
}

/// The `Set-Cookie` values of `answer`.
fn cookies(answer: &axum::response::Response) -> Vec<String> {
    answer
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().expect("a cookie").to_owned())
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_who_signed_in_with_two_factors_comes_back_to_a_console_session() {
    let server = server(2).await;
    let state = console(&server).await;
    let begun = begin(&state).await;
    issue(
        &server,
        "code-admin-1",
        &begun,
        OPERATOR,
        two_factors(),
        &begun.nonce,
    )
    .await;
    let answer = send(
        state.clone(),
        &callback("code-admin-1", &begun.state, ISSUER),
        Some(&begun.cookie),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::SEE_OTHER);
    assert_eq!(answer.headers()[header::LOCATION], "/admin/acme/");
    let set = cookies(&answer);
    let session = set
        .iter()
        .find_map(|cookie| cookie.strip_prefix("__Host-tessari-admin="))
        .expect("the console's session cookie");
    let (value, attributes) = session.split_once(';').expect("attributes");
    for attribute in [
        "Path=/",
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Max-Age=28800",
    ] {
        assert!(attributes.contains(attribute), "{attribute} in {session}");
    }
    assert!(
        set.iter()
            .any(|cookie| cookie.starts_with("__Host-tessari-admin-signin=;")
                && cookie.contains("Max-Age=0")),
        "the sign-in cookie is cleared: {set:?}"
    );
    let opened = server
        .storage
        .admin
        .find(
            &tenant("acme"),
            &SessionSecret::from_secret(value),
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("an answer")
        .expect("the session the cookie names");
    assert_eq!(opened.user.as_str(), OPERATOR);
    assert_eq!(opened.sid, SID);
    let binding = begun.cookie.split_once('=').expect("a pair").1;
    assert!(
        server
            .storage
            .admin
            .take(&tenant("acme"), &SigninBinding::from_secret(binding))
            .await
            .expect("an answer")
            .is_none(),
        "the sign-in was spent"
    );
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail");
    assert!(
        trail
            .iter()
            .any(|record| record.event.kind == AuditKind::ConsoleSignedIn
                && record.event.user.as_ref().map(UserId::as_str) == Some(OPERATOR))
    );
}

/// What one refusal case changes about an otherwise good return.
enum Spoil {
    State,
    Issuer,
    Verifier,
    Nonce,
    OneFactor,
    NoGrant,
    Replay,
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_bad_return_is_refused_alike_and_opens_nothing() {
    let server = server(2).await;
    let state = console(&server).await;
    for (index, spoil) in [
        Spoil::State,
        Spoil::Issuer,
        Spoil::Verifier,
        Spoil::Nonce,
        Spoil::OneFactor,
        Spoil::NoGrant,
        Spoil::Replay,
    ]
    .into_iter()
    .enumerate()
    {
        let begun = begin(&state).await;
        let code = format!("code-spoiled-{index}");
        let (user, methods, nonce) = match spoil {
            Spoil::OneFactor => (OPERATOR, vec![Method::Password], begun.nonce.clone()),
            Spoil::NoGrant => ("user-without-roles", two_factors(), begun.nonce.clone()),
            Spoil::Nonce => (OPERATOR, two_factors(), "another-nonce".to_owned()),
            _ => (OPERATOR, two_factors(), begun.nonce.clone()),
        };
        let issued_for = match spoil {
            // A code bound to another browser's challenge.
            Spoil::Verifier => Begun {
                challenge: Challenge::of("someone-elses-verifier-0123456789-0123456789")
                    .expect("a challenge")
                    .as_str()
                    .to_owned(),
                ..begin(&state).await
            },
            _ => Begun {
                cookie: begun.cookie.clone(),
                state: begun.state.clone(),
                nonce: begun.nonce.clone(),
                challenge: begun.challenge.clone(),
            },
        };
        issue(&server, &code, &issued_for, user, methods, &nonce).await;
        if let Spoil::Replay = spoil {
            let first = begin(&state).await;
            issue(
                &server,
                "code-replayed",
                &first,
                OPERATOR,
                two_factors(),
                &first.nonce,
            )
            .await;
            let spent = send(
                state.clone(),
                &callback("code-replayed", &first.state, ISSUER),
                Some(&first.cookie),
            )
            .await;
            assert_eq!(
                spent.status(),
                StatusCode::SEE_OTHER,
                "the first return opens a session"
            );
        }
        let (sent_code, sent_state, iss) = match spoil {
            Spoil::State => (code.as_str(), "a-state-nobody-sent", ISSUER),
            Spoil::Issuer => (
                code.as_str(),
                begun.state.as_str(),
                "https://id.example.com/initech",
            ),
            Spoil::Replay => ("code-replayed", begun.state.as_str(), ISSUER),
            _ => (code.as_str(), begun.state.as_str(), ISSUER),
        };
        let response = send(
            state.clone(),
            &callback(sent_code, sent_state, iss),
            Some(&begun.cookie),
        )
        .await;
        let set = cookies(&response);
        let refused = answer(response).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "case {index}");
        assert_eq!(refused.body["code"], "console_refused", "case {index}");
        assert!(
            set.iter()
                .all(|cookie| !cookie.starts_with("__Host-tessari-admin=")),
            "no session for case {index}: {set:?}"
        );
        let again = send(
            state.clone(),
            &callback(sent_code, &begun.state, ISSUER),
            Some(&begun.cookie),
        )
        .await;
        assert_eq!(
            again.status(),
            StatusCode::GONE,
            "the sign-in of case {index} was spent"
        );
    }
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 100)
        .await
        .expect("the trail");
    let count = |kind: AuditKind| {
        trail
            .iter()
            .filter(|record| record.event.kind == kind)
            .count()
    };
    // The replayed code would be refused by its PKCE binding as well; only its own record shows the replay was seen.
    assert_eq!(count(AuditKind::CodeReplayed), 1, "the replay is named");
    assert_eq!(
        count(AuditKind::Refused),
        6,
        "each other refusal is audited once"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_return_without_its_sign_in_cookie_starts_again() {
    let server = server(2).await;
    let state = console(&server).await;
    let begun = begin(&state).await;
    let answer = send(state, &callback("any-code", &begun.state, ISSUER), None).await;
    assert_eq!(answer.status(), StatusCode::GONE);
    assert!(answer.headers().get(header::SET_COOKIE).is_none());
}
