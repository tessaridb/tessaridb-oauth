//! Operators in the console: an operator grants and revokes only roles they hold themselves, only to active accounts
//! of their own company, never to themselves, and never for good: a grant made here expires. The list shows only the
//! grants of roles the viewer holds.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::operators::{OperatorGrant, OperatorRole};
use tessari_oauth_storage::users::{Registered, UserStatus};
use tessari_oauth_types::{EmailAddress, Timestamp, UserId};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, Server, server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const DAY: u64 = 86_400;

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

/// `what` (`grants/<role>` or `grants/<role>/revoke`) for `user`, sent by the console session `secret`.
fn granting(user: &str, what: &str, secret: &str, key: &str, body: &str) -> Request<Body> {
    Request::post(format!("/admin/acme/api/operators/{user}/{what}"))
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

async fn listed(state: AdminState, secret: &str) -> Vec<(String, String)> {
    let page = send(
        state,
        Request::get("/admin/acme/api/operators")
            .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(page.status, StatusCode::OK, "{:?}", page.body);
    let mut grants: Vec<(String, String)> = page.body["operators"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|grant| {
            (
                grant["user"].as_str().expect("a user").to_owned(),
                grant["role"].as_str().expect("a role").to_owned(),
            )
        })
        .collect();
    grants.sort();
    grants
}

async fn held(server: &Server, user: &UserId) -> Vec<(OperatorRole, Option<Timestamp>)> {
    let mut roles: Vec<(OperatorRole, Option<Timestamp>)> = server
        .storage
        .operators
        .grants(&tenant("acme"), user, Timestamp::from_unix_secs(NOW))
        .await
        .expect("an answer")
        .into_iter()
        .map(|grant| (grant.role, grant.expires_at))
        .collect();
    roles.sort_by_key(|(role, _)| role.name());
    roles
}

const WHY: &str = r#"{"reason":"joins the support rota"}"#;

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_grants_and_revokes_only_roles_they_hold_and_every_grant_expires() {
    let server = server(2).await;
    let lead = registered(&server, "acme", "lead@acme.example").await;
    let kim = registered(&server, "acme", "kim@acme.example").await;
    let state = signed_in_as(
        &server,
        lead.as_str(),
        &[OperatorRole::Users, OperatorRole::Audit],
        "issuer-lead",
        "console-lead",
    )
    .await;
    let lead_secret = "console-lead";

    let granted = send(
        state.clone(),
        granting(
            kim.as_str(),
            "grants/users",
            lead_secret,
            "grant-kim-users-1",
            WHY,
        ),
    )
    .await;
    assert_eq!(granted.status, StatusCode::OK, "{:?}", granted.body);
    assert_eq!(granted.body["user"], kim.as_str());
    assert_eq!(granted.body["role"], "users");
    assert_eq!(granted.body["granted_by"], lead.as_str());
    assert_eq!(granted.body["expires_at"], NOW + 90 * DAY);
    let week = send(
        state.clone(),
        granting(
            kim.as_str(),
            "grants/audit",
            lead_secret,
            "grant-kim-audit-1",
            r#"{"reason":"quarter close","valid_days":7}"#,
        ),
    )
    .await;
    assert_eq!(week.status, StatusCode::OK, "{:?}", week.body);
    assert_eq!(
        held(&server, &kim).await,
        [
            (
                OperatorRole::Audit,
                Some(Timestamp::from_unix_secs(NOW + 7 * DAY))
            ),
            (
                OperatorRole::Users,
                Some(Timestamp::from_unix_secs(NOW + 90 * DAY))
            ),
        ]
    );

    let refusals = [
        (
            kim.as_str(),
            "grants/policy",
            WHY,
            StatusCode::FORBIDDEN,
            "role_required",
        ),
        (
            lead.as_str(),
            "grants/audit",
            WHY,
            StatusCode::CONFLICT,
            "self_grant",
        ),
        (
            kim.as_str(),
            "grants/audit",
            r#"{"reason":"forever","valid_days":366}"#,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            kim.as_str(),
            "grants/audit",
            r#"{"reason":"never","valid_days":0}"#,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            "user-nobody",
            "grants/audit",
            WHY,
            StatusCode::NOT_FOUND,
            "user_not_found",
        ),
        (
            kim.as_str(),
            "grants/policy/revoke",
            WHY,
            StatusCode::FORBIDDEN,
            "role_required",
        ),
    ];
    for (number, (user, what, body, status, code)) in refusals.into_iter().enumerate() {
        let key = format!("refused-grant-{number:04}");
        let refused = send(state.clone(), granting(user, what, lead_secret, &key, body)).await;
        assert_eq!(refused.status, status, "{what} {body}");
        assert_eq!(refused.body["code"], code, "{what} {body}");
    }
    assert_eq!(held(&server, &kim).await.len(), 2);

    server
        .storage
        .operators
        .grant(
            &tenant("acme"),
            &OperatorGrant {
                user: kim.clone(),
                role: OperatorRole::Policy,
                granted_by: "operator-1".to_owned(),
                granted_at: Timestamp::from_unix_secs(NOW),
                reason: "policy owner".to_owned(),
                expires_at: None,
            },
        )
        .await
        .expect("granted");
    let seen = listed(state.clone(), lead_secret).await;
    let kim_id = kim.as_str().to_owned();
    let lead_id = lead.as_str().to_owned();
    let mut expected = vec![
        (kim_id.clone(), "audit".to_owned()),
        (kim_id.clone(), "users".to_owned()),
        (lead_id.clone(), "audit".to_owned()),
        (lead_id, "users".to_owned()),
    ];
    expected.sort();
    assert_eq!(seen, expected, "policy grants are not the viewer's to see");

    let revoked = send(
        state.clone(),
        granting(
            kim.as_str(),
            "grants/users/revoke",
            lead_secret,
            "revoke-kim-users-1",
            WHY,
        ),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);
    assert_eq!(revoked.body["revoked"], true);
    let again = send(
        state.clone(),
        granting(
            kim.as_str(),
            "grants/users/revoke",
            lead_secret,
            "revoke-kim-users-2",
            WHY,
        ),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.body["code"], "not_granted");
    assert_eq!(
        held(&server, &kim)
            .await
            .into_iter()
            .map(|(role, _)| role)
            .collect::<Vec<_>>(),
        [OperatorRole::Audit, OperatorRole::Policy]
    );

    let moved = server
        .storage
        .users
        .set_status(
            &tenant("acme"),
            &kim,
            UserStatus::Active,
            UserStatus::Disabled,
        )
        .await
        .expect("an answer");
    assert!(moved);
    let disabled = send(
        state,
        granting(
            kim.as_str(),
            "grants/users",
            lead_secret,
            "grant-kim-users-2",
            WHY,
        ),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::CONFLICT);
    assert_eq!(disabled.body["code"], "account_disabled");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn another_company_account_is_not_granted_and_an_auditor_sees_only_audit_grants() {
    let server = server(2).await;
    let dee = registered(&server, "initech", "dee@initech.example").await;
    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;
    let foreign = send(
        state,
        granting(
            dee.as_str(),
            "grants/users",
            "console-u",
            "grant-dee-users-1",
            WHY,
        ),
    )
    .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    assert_eq!(foreign.body["code"], "user_not_found");
    let initech_roles = server
        .storage
        .operators
        .grants(&tenant("initech"), &dee, Timestamp::from_unix_secs(NOW))
        .await
        .expect("an answer");
    assert!(initech_roles.is_empty());

    let auditor = signed_in_as(
        &server,
        "operator-a",
        &[OperatorRole::Audit],
        "issuer-a",
        "console-a",
    )
    .await;
    assert_eq!(
        listed(auditor, "console-a").await,
        [("operator-a".to_owned(), "audit".to_owned())]
    );
}
