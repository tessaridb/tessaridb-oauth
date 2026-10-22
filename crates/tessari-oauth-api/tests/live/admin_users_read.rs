//! An operator holding `users` reads their company's accounts a page at a time, in id order, behind a cursor and with
//! no total, or finds one by the exact address they already hold. Addresses are masked in every answer; only the
//! company's own accounts are listed or found, and nobody without `users` reads them.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::Registered;
use tessari_oauth_types::{EmailAddress, Timestamp, UserId};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, Server, server, tenant};

async fn registered(server: &Server, company: &str, email: &str) -> UserId {
    let address = EmailAddress::parse(email).expect("an address");
    match server
        .storage
        .users
        .register(&tenant(company), &address, Timestamp::from_unix_secs(NOW))
        .await
        .expect("registered")
    {
        Registered::Created(user) => user,
        Registered::AddressTaken => panic!("{email} is taken"),
    }
}

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

/// The user ids a list answer names, in order.
fn ids(listed: &Answer) -> Vec<String> {
    listed.body["users"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|account| account["user"].as_str().expect("an id").to_owned())
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_company_accounts_are_read_a_page_at_a_time_with_their_addresses_masked() {
    let server = server(2).await;
    let mut accounts = Vec::new();
    for email in ["anna@acme.example", "ben@acme.example", "cy@acme.example"] {
        accounts.push(registered(&server, "acme", email).await);
    }
    let ben = accounts[1].clone();
    accounts.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    let elsewhere = registered(&server, "initech", "dee@initech.example").await;
    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;

    let first = read(state.clone(), "/admin/acme/api/users?limit=2", "console-u").await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.body);
    assert_eq!(ids(&first), [accounts[0].as_str(), accounts[1].as_str()]);
    assert_eq!(first.body["next"], accounts[1].as_str());
    assert!(first.body.get("total").is_none());
    let after = format!(
        "/admin/acme/api/users?limit=2&after={}",
        first.body["next"].as_str().expect("a cursor")
    );
    let second = read(state.clone(), &after, "console-u").await;
    assert_eq!(second.status, StatusCode::OK, "{:?}", second.body);
    assert_eq!(ids(&second), [accounts[2].as_str()]);
    assert!(second.body["next"].is_null());

    for page in [&first, &second] {
        let text = page.body.to_string();
        for full in ["anna@acme.example", "ben@acme.example", "cy@acme.example"] {
            assert!(!text.contains(full), "{full} unmasked in {text}");
        }
        assert!(!text.contains(elsewhere.as_str()));
    }
    let masked: Vec<&str> = first.body["users"]
        .as_array()
        .expect("a list")
        .iter()
        .chain(second.body["users"].as_array().expect("a list"))
        .map(|account| account["email"].as_str().expect("an address"))
        .collect();
    let mut sorted = masked.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        [
            "a***@acme.example",
            "b***@acme.example",
            "c***@acme.example"
        ]
    );
    assert_eq!(first.body["users"][0]["status"], "active");
    assert_eq!(first.body["users"][0]["email_verified"], false);

    let found = read(
        state.clone(),
        "/admin/acme/api/users?email=ben@acme.example",
        "console-u",
    )
    .await;
    assert_eq!(found.status, StatusCode::OK, "{:?}", found.body);
    assert_eq!(ids(&found), [ben.as_str()]);
    for absent in ["nobody@acme.example", "dee@initech.example"] {
        let none = read(
            state.clone(),
            &format!("/admin/acme/api/users?email={absent}"),
            "console-u",
        )
        .await;
        assert_eq!(none.status, StatusCode::OK, "{absent}");
        assert_eq!(ids(&none), Vec::<String>::new(), "{absent}");
    }

    let one = read(
        state.clone(),
        &format!("/admin/acme/api/users/{}", ben.as_str()),
        "console-u",
    )
    .await;
    assert_eq!(one.status, StatusCode::OK, "{:?}", one.body);
    assert_eq!(one.body["user"], ben.as_str());
    assert_eq!(one.body["email"], "b***@acme.example");
    let foreign = read(
        state.clone(),
        &format!("/admin/acme/api/users/{}", elsewhere.as_str()),
        "console-u",
    )
    .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    assert_eq!(foreign.body["code"], "user_not_found");

    for limit in ["0", "101", "many"] {
        let refused = read(
            state.clone(),
            &format!("/admin/acme/api/users?limit={limit}"),
            "console-u",
        )
        .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "limit {limit}");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn nobody_without_users_reads_the_accounts() {
    let server = server(2).await;
    let kim = registered(&server, "acme", "kim@acme.example").await;
    let auditor = signed_in_as(
        &server,
        "operator-a",
        &[OperatorRole::Audit],
        "issuer-a",
        "console-a",
    )
    .await;
    for path in [
        "/admin/acme/api/users".to_owned(),
        "/admin/acme/api/users?email=kim@acme.example".to_owned(),
        format!("/admin/acme/api/users/{}", kim.as_str()),
    ] {
        let refused = read(auditor.clone(), &path, "console-a").await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{path}");
        assert_eq!(refused.body["code"], "role_required", "{path}");
        assert!(!refused.body.to_string().contains("kim"), "{path}");
    }
}
