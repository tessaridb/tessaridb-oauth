//! An operator holding `users` makes a group of their company, sets the roles it carries, adds and removes members,
//! reads it a page at a time, and deletes it with its memberships; every change is recorded with its reason, and
//! a name outside the grammar, an account of no company and a group that is not there are each refused.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tessari_oauth_api::{AdminState, admin_router};
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::operators::OperatorRole;
use tessari_oauth_storage::users::Registered;
use tessari_oauth_types::{EmailAddress, GroupId, Timestamp, UserId};
use tower::ServiceExt;

use crate::admin_session::signed_in_as;
use crate::routes::{Answer, answer};
use crate::token_fixture::{NOW, server, tenant};

const CONSOLE: &str = "https://admin.example.com";
const SECRET: &str = "console-g";

async fn send(state: AdminState, request: Request<Body>) -> Answer {
    answer(
        admin_router(state)
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await
}

fn change(path: &str, key: &str, body: &str) -> Request<Body> {
    Request::post(format!("/admin/acme/{path}"))
        .header(header::COOKIE, format!("__Host-tessari-admin={SECRET}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, CONSOLE)
        .header("idempotency-key", key)
        .body(Body::from(body.to_owned()))
        .expect("a request")
}

fn read(path: &str) -> Request<Body> {
    Request::get(format!("/admin/acme/{path}"))
        .header(header::COOKIE, format!("__Host-tessari-admin={SECRET}"))
        .body(Body::empty())
        .expect("a request")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_operator_runs_a_group_from_making_it_to_deleting_it() {
    let server = server(2).await;
    let state = signed_in_as(
        &server,
        "operator-g",
        &[OperatorRole::Users],
        "issuer-g",
        SECRET,
    )
    .await;
    let at = Timestamp::from_unix_secs(NOW);
    let Registered::Created(member) = server
        .storage
        .users
        .register(
            &tenant("acme"),
            &EmailAddress::parse("ada@example.com").expect("an address"),
            at,
        )
        .await
        .expect("registered")
    else {
        panic!("a new account");
    };

    let made = send(
        state.clone(),
        change(
            "api/groups",
            "group-make-000001",
            r#"{"group":"staff","description":"everyone at the desk","roles":["reader"],"reason":"ticket 11"}"#,
        ),
    )
    .await;
    assert_eq!(made.status, StatusCode::CREATED, "{:?}", made.body);
    assert_eq!(made.body["group"], "staff");
    assert_eq!(made.body["roles"], serde_json::json!(["reader"]));
    let taken = send(
        state.clone(),
        change(
            "api/groups",
            "group-make-000002",
            r#"{"group":"staff","reason":"again"}"#,
        ),
    )
    .await;
    assert_eq!(taken.status, StatusCode::CONFLICT, "{:?}", taken.body);
    assert_eq!(taken.body["code"], "group_taken");
    for (number, refused) in [
        r#"{"group":"Staff","reason":"x"}"#,
        r#"{"group":"ops","roles":["Admin"],"reason":"x"}"#,
        r#"{"group":"ops","reason":"x","tenant":"initech"}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let answered = send(
            state.clone(),
            change("api/groups", &format!("group-refused-{number:04}"), refused),
        )
        .await;
        assert_eq!(answered.status, StatusCode::BAD_REQUEST, "{refused}");
    }

    let roles = send(
        state.clone(),
        change(
            "api/groups/staff/roles",
            "group-roles-00001",
            r#"{"roles":["writer","reader"],"reason":"desk edits now"}"#,
        ),
    )
    .await;
    assert_eq!(roles.status, StatusCode::OK, "{:?}", roles.body);
    assert_eq!(roles.body["roles"], serde_json::json!(["reader", "writer"]));
    let nowhere = send(
        state.clone(),
        change(
            "api/groups/nobody/roles",
            "group-roles-00002",
            r#"{"roles":[],"reason":"x"}"#,
        ),
    )
    .await;
    assert_eq!(nowhere.status, StatusCode::NOT_FOUND, "{:?}", nowhere.body);
    assert_eq!(nowhere.body["code"], "group_not_found");

    let added = send(
        state.clone(),
        change(
            "api/groups/staff/members",
            "group-member-0001",
            &format!(
                r#"{{"user":"{}","reason":"joined the desk"}}"#,
                member.as_str()
            ),
        ),
    )
    .await;
    assert_eq!(added.status, StatusCode::OK, "{:?}", added.body);
    let stranger = send(
        state.clone(),
        change(
            "api/groups/staff/members",
            "group-member-0002",
            r#"{"user":"user-of-nobody","reason":"x"}"#,
        ),
    )
    .await;
    assert_eq!(
        stranger.status,
        StatusCode::NOT_FOUND,
        "{:?}",
        stranger.body
    );
    assert_eq!(stranger.body["code"], "user_not_found");

    let listed = send(state.clone(), read("api/groups/staff/members")).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.body);
    assert_eq!(listed.body["members"][0]["user"], member.as_str());
    assert_eq!(listed.body["members"][0]["added_by"], "operator-g");
    let groups = send(state.clone(), read("api/groups?limit=1")).await;
    assert_eq!(groups.status, StatusCode::OK, "{:?}", groups.body);
    assert_eq!(groups.body["groups"][0]["group"], "staff");
    assert_eq!(groups.body["next"], "staff");
    let missing = send(state.clone(), read("api/groups/nobody")).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let left = send(
        state.clone(),
        change(
            &format!("api/groups/staff/members/{}/remove", member.as_str()),
            "group-leave-00001",
            r#"{"reason":"moved teams"}"#,
        ),
    )
    .await;
    assert_eq!(left.status, StatusCode::OK, "{:?}", left.body);
    let again = send(
        state.clone(),
        change(
            &format!("api/groups/staff/members/{}/remove", member.as_str()),
            "group-leave-00002",
            r#"{"reason":"twice"}"#,
        ),
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND, "{:?}", again.body);
    assert_eq!(again.body["code"], "member_not_found");

    let removed = send(
        state.clone(),
        change(
            "api/groups/staff/remove",
            "group-remove-0001",
            r#"{"reason":"desk closed"}"#,
        ),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);
    assert!(
        server
            .storage
            .groups
            .find(
                &tenant("acme"),
                &GroupId::parse("staff").expect("a group id")
            )
            .await
            .expect("answered")
            .is_none()
    );
    let trail = server
        .storage
        .audit
        .read_after(&tenant("acme"), 0, 500)
        .await
        .expect("the trail reads");
    for (action, reason) in [
        ("groups.create", "ticket 11"),
        ("groups.roles", "desk edits now"),
        ("groups.members.add", "joined the desk"),
        ("groups.members.remove", "moved teams"),
        ("groups.remove", "desk closed"),
    ] {
        assert!(
            trail.iter().any(|message| {
                message.event.kind == AuditKind::AdminAction
                    && message.event.action.as_deref() == Some(action)
                    && message.event.reason.as_deref() == Some(reason)
            }),
            "{action} recorded with its reason"
        );
    }
    let in_trail = trail.iter().any(|message| {
        message.event.action.as_deref() == Some("groups.members.add")
            && message.event.user.as_ref() == Some(&UserId::parse(member.as_str()).expect("an id"))
    });
    assert!(in_trail, "the member is named on the record");
}
