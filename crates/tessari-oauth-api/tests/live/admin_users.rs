//! An operator holding `users` disables an account of their own company, and the account loses everything it held at
//! once: its sessions, its refresh families and, when it is an operator too, its console. Enabling it gives back only
//! the right to sign in. Each move is made from the status the account is in, once per key, and recorded with why;
//! nobody without `users`, and no account of another company, gets as far as the change.

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::refresh::{RefreshGrant, Rotation, RotationRefusal};
use tessari_oauth_storage::users::{Registered, UserStatus};
use tessari_oauth_types::{
    ClientId, EmailAddress, RefreshToken, Resource, ScopeSet, SessionSecret, Timestamp, UserId,
};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, Server, server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const LEFT: &str = r#"{"reason":"left the company"}"#;

/// A new active account of `company` signing in with `email`.
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

/// A console change `what` (`disable` or `enable`) of `user` at `company`, by the console session `secret`.
fn moved(company: &str, user: &str, what: &str, secret: &str, key: &str) -> Request<Body> {
    Request::post(format!("/admin/{company}/api/users/{user}/{what}"))
        .header(header::COOKIE, format!("__Host-tessari-admin={secret}"))
        .header(header::ORIGIN, CONSOLE)
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", key)
        .body(Body::from(LEFT))
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

async fn status(server: &Server, company: &str, user: &UserId) -> UserStatus {
    server
        .storage
        .users
        .find(&tenant(company), user)
        .await
        .expect("an answer")
        .expect("the account")
        .status
}

fn token(name: &str) -> RefreshToken {
    RefreshToken::from_secret(format!("refresh-{name}-0123456789-0123456789-0123456789"))
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn disabling_an_account_ends_its_sessions_families_and_console_and_enabling_restores_sign_in()
{
    let server = server(2).await;
    let kim = registered(&server, "acme", "kim@acme.example").await;
    signed_in_as(
        &server,
        kim.as_str(),
        &[OperatorRole::Audit],
        "issuer-kim",
        "console-kim",
    )
    .await;
    let grant = RefreshGrant {
        tenant: tenant("acme"),
        user: kim.clone(),
        client_id: ClientId::parse("portal").expect("a client id"),
        scopes: ScopeSet::parse("api:read").expect("scopes"),
        resources: BTreeSet::from([
            Resource::parse("https://api.example.com/").expect("a resource")
        ]),
        bound_to: None,
    };
    server
        .storage
        .refresh
        .start(
            &token("kim"),
            &grant,
            "family-kim",
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("started");
    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;

    let disabled = send(
        state.clone(),
        moved(
            "acme",
            kim.as_str(),
            "disable",
            "console-u",
            "disable-kim-0001",
        ),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK, "{:?}", disabled.body);
    assert_eq!(disabled.body["user"], kim.as_str());
    assert_eq!(disabled.body["status"], "disabled");
    assert_eq!(disabled.body["sessions"], 1);
    assert_eq!(disabled.body["families"], 1);
    assert_eq!(status(&server, "acme", &kim).await, UserStatus::Disabled);
    let rotation = server
        .storage
        .refresh
        .rotate(
            &tenant("acme"),
            &token("kim"),
            &token("kim-next"),
            &grant.client_id,
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("answered");
    assert!(
        matches!(rotation, Rotation::Refused(RotationRefusal::FamilyRevoked)),
        "{rotation:?}"
    );
    let own_console = send(
        state.clone(),
        Request::get("/admin/acme/api/me")
            .header(header::COOKIE, "__Host-tessari-admin=console-kim")
            .body(Body::empty())
            .expect("a request"),
    )
    .await;
    assert_eq!(own_console.status, StatusCode::UNAUTHORIZED);
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 500)
        .await
        .expect("the trail reads");
    assert!(trail.iter().any(|message| {
        message.event.kind == AuditKind::Cascade
            && message.event.user.as_ref() == Some(&kim)
            && message.event.reason.as_deref() == Some("user_disabled")
    }));
    assert!(trail.iter().any(|message| {
        message.event.kind == AuditKind::AdminAction
            && message.event.action.as_deref() == Some("users.disable")
            && message.event.user.as_ref() == Some(&kim)
            && message.event.reason.as_deref() == Some("left the company")
    }));

    let repeated = send(
        state.clone(),
        moved(
            "acme",
            kim.as_str(),
            "disable",
            "console-u",
            "disable-kim-0001",
        ),
    )
    .await;
    assert_eq!(repeated.status, StatusCode::OK);
    assert_eq!(repeated.body, disabled.body);
    // A cascade that did not finish leaves a disabled account holding a session; sending the disable again ends it.
    let left_over = SessionSecret::from_secret("issuer-kim-left-over");
    server
        .storage
        .sessions
        .create(
            &tenant("acme"),
            &left_over,
            &kim,
            &[Method::Password],
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("a session");
    let again = send(
        state.clone(),
        moved(
            "acme",
            kim.as_str(),
            "disable",
            "console-u",
            "disable-kim-0002",
        ),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.body["code"], "changed_meanwhile");
    let ended = server
        .storage
        .sessions
        .find(&tenant("acme"), &left_over, Timestamp::from_unix_secs(NOW))
        .await
        .expect("an answer");
    assert!(ended.is_none(), "the left-over session still stands");

    let enabled = send(
        state.clone(),
        moved(
            "acme",
            kim.as_str(),
            "enable",
            "console-u",
            "enable-kim-00001",
        ),
    )
    .await;
    assert_eq!(enabled.status, StatusCode::OK, "{:?}", enabled.body);
    assert_eq!(enabled.body["status"], "active");
    assert_eq!(status(&server, "acme", &kim).await, UserStatus::Active);
    let enabled_again = send(
        state,
        moved(
            "acme",
            kim.as_str(),
            "enable",
            "console-u",
            "enable-kim-00002",
        ),
    )
    .await;
    assert_eq!(enabled_again.status, StatusCode::CONFLICT);
    assert_eq!(enabled_again.body["code"], "changed_meanwhile");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn only_an_operator_holding_users_moves_an_account_and_only_one_of_their_company() {
    let server = server(2).await;
    let kim = registered(&server, "acme", "kim@acme.example").await;
    let bo = registered(&server, "initech", "bo@initech.example").await;
    let auditor = signed_in_as(
        &server,
        "operator-a",
        &[OperatorRole::Audit],
        "issuer-a",
        "console-a",
    )
    .await;
    let refused = send(
        auditor,
        moved(
            "acme",
            kim.as_str(),
            "disable",
            "console-a",
            "disable-kim-0003",
        ),
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.body["code"], "role_required");
    assert_eq!(status(&server, "acme", &kim).await, UserStatus::Active);

    let state = signed_in_as(
        &server,
        "operator-u",
        &[OperatorRole::Users],
        "issuer-u",
        "console-u",
    )
    .await;
    for (user, key) in [
        (bo.as_str(), "disable-bo-00001"),
        ("user-nobody", "disable-nobody-1"),
    ] {
        let missing = send(
            state.clone(),
            moved("acme", user, "disable", "console-u", key),
        )
        .await;
        assert_eq!(missing.status, StatusCode::NOT_FOUND, "{user}");
        assert_eq!(missing.body["code"], "user_not_found", "{user}");
    }
    assert_eq!(status(&server, "initech", &bo).await, UserStatus::Active);
}
