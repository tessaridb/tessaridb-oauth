//! An operator holding `clients` reads their company's client registrations a page at a time in id order, or one by
//! its id: how each authenticates, where it may redirect, what it may ask for and where its tokens may go, with the
//! server's own console client marked as such. Only the company's own registrations are listed or found.

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_core::clients::{AuthMethod, GrantType};
use tessari_oauth_storage::audit::AuditKind;
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
        sector: None,
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
    assert!(
        portal.body["sector"].is_null(),
        "a client with no sector is its own"
    );
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

const CONSOLE: &str = "https://admin.example.com";

fn registering(secret: &str, key: &str, body: &str) -> Request<Body> {
    Request::post("/admin/acme/api/clients")
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, CONSOLE)
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

/// RFC 8037 §A.2: an Ed25519 public key.
const ED25519_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

const SHOP: &str = r#"{"client_id":"shop","redirect_uris":["https://shop.example/cb"],
"scope_ceiling":["openid","orders:read"],"resources":["https://api.example/orders"],"auth_method":"none",
"grant_types":["authorization_code","refresh_token"],"reason":"new storefront, ticket 7"}"#;

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_registers_a_client_once_through_the_registration_rules() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-c",
        &[OperatorRole::Clients],
        "issuer-c",
        "console-c",
    )
    .await;
    let made = send(
        state.clone(),
        registering("console-c", "register-shop-001", SHOP),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.body);
    assert_eq!(made.body["client_id"], "shop");
    assert_eq!(made.body["kind"], "public");
    assert_eq!(
        made.body["redirect_uris"],
        serde_json::json!(["https://shop.example/cb"])
    );
    let found = server
        .storage
        .clients
        .find(
            &tenant("acme"),
            &ClientId::parse("shop").expect("a client id"),
        )
        .await
        .expect("an answer")
        .expect("registered");
    assert_eq!(found.auth_method, AuthMethod::None);
    assert_eq!(
        found.grant_types,
        [GrantType::AuthorizationCode, GrantType::RefreshToken]
    );
    let elsewhere = server
        .storage
        .clients
        .find(
            &tenant("initech"),
            &ClientId::parse("shop").expect("a client id"),
        )
        .await
        .expect("an answer");
    assert!(
        elsewhere.is_none(),
        "registered in the operator's company only"
    );
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 500)
        .await
        .expect("the trail reads");
    assert!(trail.iter().any(|message| {
        message.event.kind == AuditKind::AdminAction
            && message.event.action.as_deref() == Some("clients.register")
            && message.event.reason.as_deref() == Some("new storefront, ticket 7")
    }));
    let repeated = send(
        state.clone(),
        registering("console-c", "register-shop-001", SHOP),
    )
    .await;
    assert_eq!(repeated.status, StatusCode::CREATED);
    assert_eq!(repeated.body, made.body);

    let taken = send(
        state.clone(),
        registering("console-c", "register-shop-002", SHOP),
    )
    .await;
    assert_eq!(taken.status, StatusCode::CONFLICT, "{:?}", taken.body);
    assert_eq!(taken.body["code"], "client_taken");
    let console = SHOP.replace(r#""client_id":"shop""#, r#""client_id":"admin-console""#);
    let reserved = send(
        state.clone(),
        registering("console-c", "register-cons-001", &console),
    )
    .await;
    assert_eq!(reserved.status, StatusCode::CONFLICT, "{:?}", reserved.body);
    assert_eq!(reserved.body["code"], "client_reserved");

    let signed = format!(
        r#"{{"client_id":"svc","redirect_uris":[],"scope_ceiling":["orders:read"],"auth_method":"private_key_jwt",
"assertion_alg":"EdDSA","jwks":[{}],"grant_types":["client_credentials"],"sector":"billing",
"reason":"billing job"}}"#,
        ED25519_JWK
    );
    let confidential = send(
        state.clone(),
        registering("console-c", "register-svc-0001", &signed),
    )
    .await;
    assert_eq!(
        confidential.status,
        StatusCode::CREATED,
        "{:?}",
        confidential.body
    );
    assert_eq!(confidential.body["kind"], "confidential");
    assert_eq!(confidential.body["assertion_alg"], "EdDSA");
    assert_eq!(confidential.body["keys"], 1);
    assert_eq!(confidential.body["sector"], "billing");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_registration_outside_the_rules_is_refused_and_nothing_is_written() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-c",
        &[OperatorRole::Clients],
        "issuer-c",
        "console-c",
    )
    .await;
    let cases = [
        // a shared secret this server cannot verify at its token endpoint
        SHOP.replace(
            r#""auth_method":"none""#,
            r#""auth_method":"client_secret_basic""#,
        ),
        // a public client acting as itself
        SHOP.replace(
            r#""authorization_code","refresh_token""#,
            r#""client_credentials""#,
        ),
        // keys for a client that does not sign
        SHOP.replace(
            r#""auth_method":"none""#,
            &format!(r#""auth_method":"none","jwks":[{ED25519_JWK}]"#),
        ),
        // an assertion algorithm without private_key_jwt
        SHOP.replace(
            r#""auth_method":"none""#,
            r#""auth_method":"none","assertion_alg":"EdDSA""#,
        ),
        // plain http off the loopback
        SHOP.replace("https://shop.example/cb", "http://shop.example/cb"),
        // a code flow with nowhere to send the code
        SHOP.replace(r#"["https://shop.example/cb"]"#, "[]"),
        // no grant at all
        SHOP.replace(r#"["authorization_code","refresh_token"]"#, "[]"),
        // a grant this server does not know
        SHOP.replace(r#""refresh_token""#, r#""password""#),
        // a sector that is not a name
        SHOP.replace(
            r#""client_id":"shop""#,
            r#""client_id":"shop","sector":"Shop Family""#,
        ),
        // a field outside the allow-list, such as another company
        SHOP.replace(
            r#""client_id":"shop""#,
            r#""client_id":"shop","tenant":"initech""#,
        ),
    ];
    for (number, case) in cases.iter().enumerate() {
        let key = format!("refused-shop-{number:04}");
        let refused = send(state.clone(), registering("console-c", &key, case)).await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "case {number}: {:?}",
            refused.body
        );
    }
    let found = server
        .storage
        .clients
        .find(
            &tenant("acme"),
            &ClientId::parse("shop").expect("a client id"),
        )
        .await
        .expect("an answer");
    assert!(found.is_none(), "no refused registration was written");
}

fn removing(secret: &str, key: &str, client: &str) -> Request<Body> {
    Request::post(format!("/admin/acme/api/clients/{client}/remove"))
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, CONSOLE)
        .header("idempotency-key", key)
        .body(Body::from(r#"{"reason":"storefront retired, ticket 9"}"#))
        .expect("a request")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_removes_a_client_and_every_grant_and_family_it_held_ends_with_it() {
    use tessari_oauth_core::consents::ConsentRequest;
    use tessari_oauth_storage::consents::NewGrant;
    use tessari_oauth_storage::refresh::{Holder, RefreshGrant};
    use tessari_oauth_types::{RefreshToken, UserId};

    let server = server(2).await;
    let at = Timestamp::from_unix_secs(NOW);
    server
        .storage
        .provision_company(&tenant("acme"), "https://id.example.com", CONSOLE, at)
        .await
        .expect("provisioned");
    let state = signed_in_as(
        &server,
        "operator-c",
        &[OperatorRole::Clients],
        "issuer-c",
        "console-c",
    )
    .await;
    let portal = ClientId::parse("portal").expect("a client id");
    for who in ["user-7", "user-8"] {
        server
            .storage
            .consents
            .grant(&NewGrant {
                tenant: tenant("acme"),
                user: UserId::parse(who).expect("a user id"),
                client_id: portal.clone(),
                request: ConsentRequest {
                    scopes: ScopeSet::parse("api:read").expect("scopes"),
                    resources: BTreeSet::new(),
                },
                policy_version: 1,
                shown_version: "descriptions-v1".to_owned(),
                at,
            })
            .await
            .expect("granted");
    }
    let grant = RefreshGrant {
        tenant: tenant("acme"),
        user: UserId::parse("user-7").expect("a user id"),
        client_id: portal.clone(),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        resources: BTreeSet::new(),
        bound_to: None,
    };
    server
        .storage
        .refresh
        .start(
            &RefreshToken::from_secret("refresh-secret-portal".to_owned()),
            &grant,
            "family-portal",
            at,
        )
        .await
        .expect("started");

    let shown = read(state.clone(), "/admin/acme/api/clients/portal", "console-c").await;
    assert_eq!(shown.status, StatusCode::OK, "{:?}", shown.body);
    assert_eq!(shown.body["holders"], 2, "the confirm panel's count");

    let removed = send(
        state.clone(),
        removing("console-c", "remove-portal-001", "portal"),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);
    assert_eq!(removed.body["client_id"], "portal");
    assert_eq!(removed.body["consents"], 2);
    assert_eq!(removed.body["families"], 1);
    assert!(removed.body["access_tokens_end_by"].as_u64() > Some(NOW));
    let gone = server
        .storage
        .clients
        .find(&tenant("acme"), &portal)
        .await
        .expect("an answer");
    assert!(gone.is_none(), "the registration is gone");
    let standing = server
        .storage
        .refresh
        .revoke_standing(&tenant("acme"), &Holder::Client(&portal), "probe", at)
        .await
        .expect("counted");
    assert_eq!(standing, 0, "no family of the client stands");
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 500)
        .await
        .expect("the trail reads");
    assert!(trail.iter().any(|message| {
        message.event.kind == AuditKind::AdminAction
            && message.event.action.as_deref() == Some("clients.remove")
            && message.event.reason.as_deref() == Some("storefront retired, ticket 9")
    }));

    let repeated = send(
        state.clone(),
        removing("console-c", "remove-portal-001", "portal"),
    )
    .await;
    assert_eq!(repeated.status, StatusCode::OK);
    assert_eq!(repeated.body, removed.body, "the kept answer");
    let nothing = send(
        state.clone(),
        removing("console-c", "remove-portal-002", "portal"),
    )
    .await;
    assert_eq!(nothing.status, StatusCode::NOT_FOUND, "{:?}", nothing.body);
    assert_eq!(nothing.body["code"], "client_not_found");
    let reserved = send(
        state.clone(),
        removing("console-c", "remove-console-01", "admin-console"),
    )
    .await;
    assert_eq!(reserved.status, StatusCode::CONFLICT, "{:?}", reserved.body);
    assert_eq!(reserved.body["code"], "client_reserved");
    let console = server
        .storage
        .clients
        .find(
            &tenant("acme"),
            &ClientId::parse("admin-console").expect("a client id"),
        )
        .await
        .expect("an answer");
    assert!(console.is_some(), "the console's own client stays");
}
