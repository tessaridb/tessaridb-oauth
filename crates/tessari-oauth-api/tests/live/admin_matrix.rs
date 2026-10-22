//! The console's negative matrix: every route the admin router serves behind a session is asked with no session, with
//! another company's session, by an operator holding only `audit`, and (for every change) from another origin. The
//! route list is the router's own, so a route added without a row here is a route nobody has probed.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::operators::OperatorRole;
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::server;

const CONSOLE: &str = "https://admin.example.com";
const WHY: &str = r#"{"reason":"matrix probe"}"#;

/// Every route behind a session: its method, its path under `/admin/{company}`, and whether a role refuses an
/// operator holding only `audit` there.
const ROUTES: [(&str, &str, bool); 22] = [
    ("GET", "api/me", false),
    ("GET", "api/policy/two-factor", true),
    ("PUT", "api/policy/two-factor", true),
    ("GET", "api/users", true),
    ("POST", "api/users", true),
    ("GET", "api/users/user-nobody", true),
    ("GET", "api/audit", false),
    ("GET", "api/companies", true),
    ("POST", "api/companies", true),
    ("POST", "api/companies/globex/suspend", true),
    ("POST", "api/companies/globex/resume", true),
    ("GET", "api/operators", false),
    ("GET", "api/clients", true),
    ("POST", "api/clients", true),
    ("GET", "api/clients/portal", true),
    ("POST", "api/operators/user-nobody/grants/users", true),
    (
        "POST",
        "api/operators/user-nobody/grants/users/revoke",
        true,
    ),
    ("POST", "api/users/user-nobody/enrolment", true),
    ("POST", "api/users/user-nobody/email/reveal", true),
    ("POST", "api/users/user-nobody/disable", true),
    ("POST", "api/users/user-nobody/enable", true),
    ("POST", "signout", false),
];

fn request(
    method: &str,
    path: &str,
    cookie: Option<&str>,
    origin: &str,
    key: &str,
) -> Request<Body> {
    let method = Method::from_bytes(method.as_bytes()).expect("a method");
    let mut request = Request::builder()
        .method(method.clone())
        .uri(path)
        .header(header::ORIGIN, origin)
        .header("idempotency-key", key);
    if let Some(secret) = cookie {
        request = request.header(header::COOKIE, format!("__Host-tessari-admin={secret}"));
    }
    if method == Method::GET {
        return request.body(Body::empty()).expect("a request");
    }
    request
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(WHY))
        .expect("a request")
}

async fn send(state: AdminState, request: Request<Body>) -> Answer {
    answer(
        admin_router(state)
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_session_route_refuses_no_session_another_company_a_low_privilege_operator_and_another_origin()
 {
    let server = server(2).await;
    let auditor = signed_in_as(
        &server,
        "operator-a",
        &[OperatorRole::Audit],
        "issuer-a",
        "console-a",
    )
    .await;
    let all = [
        OperatorRole::Users,
        OperatorRole::Clients,
        OperatorRole::Policy,
        OperatorRole::Audit,
    ];
    let lead = signed_in_as(&server, "operator-l", &all, "issuer-l", "console-l").await;
    for (number, (method, route, role_refuses)) in ROUTES.into_iter().enumerate() {
        let at_acme = format!("/admin/acme/{route}");
        let key = format!("matrix-probe-{number:04}");
        let changes = method != "GET";
        if route != "signout" {
            let none = send(
                auditor.clone(),
                request(method, &at_acme, None, CONSOLE, &key),
            )
            .await;
            assert_eq!(
                none.status,
                StatusCode::UNAUTHORIZED,
                "{method} {route}: no session"
            );
            let at_initech = format!("/admin/initech/{route}");
            let foreign = send(
                auditor.clone(),
                request(method, &at_initech, Some("console-a"), CONSOLE, &key),
            )
            .await;
            assert_eq!(
                foreign.status,
                StatusCode::UNAUTHORIZED,
                "{method} {route}: another company's session"
            );
        }
        if role_refuses {
            let low = send(
                auditor.clone(),
                request(method, &at_acme, Some("console-a"), CONSOLE, &key),
            )
            .await;
            assert_eq!(
                low.status,
                StatusCode::FORBIDDEN,
                "{method} {route}: audit only"
            );
            assert_eq!(low.body["code"], "role_required", "{method} {route}");
        }
        if changes {
            let elsewhere = send(
                lead.clone(),
                request(
                    method,
                    &at_acme,
                    Some("console-l"),
                    "https://evil.example.com",
                    &key,
                ),
            )
            .await;
            assert_eq!(
                elsewhere.status,
                StatusCode::FORBIDDEN,
                "{method} {route}: another origin"
            );
            assert_eq!(elsewhere.body["code"], "cross_origin", "{method} {route}");
        }
    }
}
