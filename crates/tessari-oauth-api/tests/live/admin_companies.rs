//! Companies are made in the `system` console only, by an operator holding `companies`: a new company is created,
//! provisioned and served at once, a taken id is refused, and a company whose creation stopped half way is completed
//! when the creation is sent again. Every company is listed there and nowhere else.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::companies::{CompanyStatus, Served};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{ClientId, Timestamp};
use tower::ServiceExt;

use crate::admin_session::{signed_in_as, signed_in_at};
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, Server, server, tenant};

const CONSOLE: &str = "https://admin.example.com";

/// The `system` console for `operator` holding `roles`, its directory prepared and the company served.
async fn system_console(server: &Server, operator: &str, roles: &[OperatorRole]) -> AdminState {
    server
        .storage
        .companies
        .prepare()
        .await
        .expect("a directory");
    server
        .storage
        .tenants
        .provision(&tenant("system"))
        .await
        .expect("provisioned");
    // `system` stands in the directory as the node makes it at start, so a refresh of what is served keeps it.
    let now = Timestamp::from_unix_secs(NOW);
    server
        .storage
        .companies
        .create(&tenant("system"), "system", "configuration", now)
        .await
        .expect("created");
    server
        .storage
        .companies
        .transition(
            &tenant("system"),
            CompanyStatus::Provisioning,
            CompanyStatus::Active,
        )
        .await
        .expect("an answer");
    let state = signed_in_at(server, "system", operator, roles, "issuer-s", "console-s").await;
    let served = Served::new("https://id.example.com");
    served.replace([tenant("system"), tenant("acme"), tenant("initech")]);
    AdminState {
        served: Arc::new(served),
        ..state
    }
}

fn post(path: &str, secret: &str, key: &str, body: &str) -> Request<Body> {
    Request::post(path)
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::ORIGIN, CONSOLE)
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(body.to_owned()))
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

const GLOBEX: &str = r#"{"id":"globex","name":"Globex","reason":"signed contract 77"}"#;

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_company_is_created_served_at_once_and_listed_in_the_system_console() {
    let server = server(2).await;
    let state = system_console(&server, "platform-1", &[OperatorRole::Companies]).await;
    let created = send(
        state.clone(),
        post(
            "/admin/system/api/companies",
            "console-s",
            "create-globex-01",
            GLOBEX,
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{:?}", created.body);
    assert_eq!(created.body["id"], "globex");
    assert_eq!(created.body["status"], "active");
    assert!(
        state.served.issuer(&tenant("globex")).is_some(),
        "not served"
    );
    let console = server
        .storage
        .clients
        .find(
            &tenant("globex"),
            &ClientId::parse("admin-console").expect("a client id"),
        )
        .await
        .expect("an answer");
    assert!(console.is_some(), "the console client was not registered");

    let taken = send(
        state.clone(),
        post(
            "/admin/system/api/companies",
            "console-s",
            "create-globex-02",
            GLOBEX,
        ),
    )
    .await;
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(taken.body["code"], "company_taken");

    // A creation that stopped before provisioning finished leaves the company in `provisioning`.
    server
        .storage
        .companies
        .create(
            &tenant("hooli"),
            "Hooli",
            "platform-1",
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("created");
    let completed = send(
        state.clone(),
        post(
            "/admin/system/api/companies",
            "console-s",
            "create-hooli-0001",
            r#"{"id":"hooli","name":"Hooli","reason":"signed contract 78"}"#,
        ),
    )
    .await;
    assert_eq!(
        completed.status,
        StatusCode::CREATED,
        "{:?}",
        completed.body
    );
    let hooli = server
        .storage
        .companies
        .find(&tenant("hooli"))
        .await
        .expect("an answer")
        .expect("the company");
    assert_eq!(hooli.status, CompanyStatus::Active);

    let listed = send(
        state,
        Request::get("/admin/system/api/companies")
            .header(header::COOKIE, "__Host-tessari-admin=console-s")
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    let companies = listed.body["companies"].as_array().expect("a list");
    let ids: Vec<&str> = companies
        .iter()
        .map(|company| company["id"].as_str().expect("an id"))
        .collect();
    assert!(ids.contains(&"globex") && ids.contains(&"hooli"), "{ids:?}");
    let globex = companies
        .iter()
        .find(|company| company["id"] == "globex")
        .expect("listed");
    assert_eq!(globex["name"], "Globex");
    assert_eq!(globex["created_by"], "platform-1");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn no_company_is_made_outside_the_system_console_or_without_companies() {
    let server = server(2).await;
    let users_only = system_console(&server, "platform-2", &[OperatorRole::Users]).await;
    let refused = send(
        users_only,
        post(
            "/admin/system/api/companies",
            "console-s",
            "create-globex-03",
            GLOBEX,
        ),
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body["code"], "role_required");
    let acme = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users, OperatorRole::Audit],
        "issuer-u",
        "console-u",
    )
    .await;
    let elsewhere = send(
        acme,
        post(
            "/admin/acme/api/companies",
            "console-u",
            "create-globex-04",
            GLOBEX,
        ),
    )
    .await;
    assert_eq!(elsewhere.status, StatusCode::FORBIDDEN);
    assert_eq!(elsewhere.body["code"], "role_required");
    let made = server
        .storage
        .companies
        .find(&tenant("globex"))
        .await
        .expect("an answer");
    assert!(made.is_none(), "a refused request made a company");
}
