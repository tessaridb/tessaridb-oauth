//! An operator holding `clients` reads their company's client registrations a page at a time in id order, or one by
//! its id: how each authenticates, where it may redirect, what it may ask for and where its tokens may go, with the
//! server's own console client marked as such. Only the company's own registrations are listed or found.

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_storage::clients::NewClient;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_types::{ClientId, RedirectUri, ScopeSet, Timestamp};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, server, tenant};

async fn read(state: AdminState, path: &str, secret: &str) -> Answer {
    answer(
        admin_router(state)
            .oneshot(
                Request::get(path)
                    .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
                    .body(Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("an answer"),
    )
    .await
}

/// The client ids a list answer names, in order.
fn ids(listed: &Answer) -> Vec<String> {
    listed.body["clients"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|client| client["client_id"].as_str().expect("an id").to_owned())
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_company_clients_are_read_a_page_at_a_time_and_one_by_id() {
    let server = server(2).await;
    let at = Timestamp::from_unix_secs(NOW);
    server
        .storage
        .provision_company(
            &tenant("acme"),
            "https://id.example.com",
            "https://admin.example.com",
            at,
        )
        .await
        .expect("provisioned");
    let elsewhere = NewClient {
        client_id: ClientId::parse("only-initech").expect("a client id"),
        redirect_uris: vec![RedirectUri::parse("https://initech.example/cb").expect("a URI")],
        scope_ceiling: ScopeSet::parse("openid").expect("scopes"),
        resources: BTreeSet::new(),
        auth_method: AuthMethod::None,
        grant_types: vec![GrantType::AuthorizationCode],
        jwks: Vec::new(),
        dpop_bound_access_tokens: false,
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
    };
    server
        .storage
        .clients
        .register(&tenant("initech"), &elsewhere, at)
        .await
        .expect("registered");
    let state = signed_in_as(
        &server,
        "operator-c",
        &[OperatorRole::Clients],
        "issuer-c",
        "console-c",
    )
    .await;

    let first = read(
        state.clone(),
        "/admin/acme/api/clients?limit=2",
        "console-c",
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    assert_eq!(ids(&first), ["admin-console", "kiosk"]);
    assert_eq!(first.body["next"], "kiosk");
    assert_eq!(first.body["clients"][0]["console"], true);
    assert_eq!(first.body["clients"][1]["console"], false);

    let rest = read(
        state.clone(),
        "/admin/acme/api/clients?limit=2&after=kiosk",
        "console-c",
    )
    .await;
    assert_eq!(rest.status, StatusCode::OK, "{:?}", rest.body);
    assert_eq!(ids(&rest), ["portal"]);
    assert!(
        rest.body["next"].is_null(),
        "a page that is not full ends the list"
    );

    let portal = read(state.clone(), "/admin/acme/api/clients/portal", "console-c").await;
    assert_eq!(portal.status, StatusCode::OK, "{:?}", portal.body);
    assert_eq!(portal.body["client_id"], "portal");
    assert_eq!(portal.body["kind"], "public");
    assert_eq!(portal.body["auth_method"], "none");
    assert_eq!(
        portal.body["grant_types"],
        serde_json::json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(
        portal.body["scope_ceiling"],
        serde_json::json!(["api:read", "api:write"])
    );
    assert_eq!(portal.body["keys"], 0);
    assert_eq!(portal.body["console"], false);

    let foreign = read(
        state.clone(),
        "/admin/acme/api/clients/only-initech",
        "console-c",
    )
    .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{:?}", foreign.body);
    assert_eq!(foreign.body["code"], "client_not_found");

    for refused in [
        "/admin/acme/api/clients?limit=0",
        "/admin/acme/api/clients?limit=101",
        "/admin/acme/api/clients?after=bad%01id",
        "/admin/acme/api/clients?colour=red",
    ] {
        let answer = read(state.clone(), refused, "console-c").await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{refused}");
    }
}
