//! Groups: made once under their id, carrying the roles they are given, holding users and never another group; a
//! delete takes every membership with it; a membership needs its group; and one company's group is not another's.

use std::collections::BTreeSet;

use tessari_oauth_storage::Storage;
use tessari_oauth_storage::groups::{GroupCreated, Joined, NewGroup};
use tessari_oauth_types::{GroupId, GroupRole, TenantId, Timestamp, UserId};

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn group(name: &str) -> GroupId {
    GroupId::parse(name).expect("a group id")
}

fn user(name: &str) -> UserId {
    UserId::parse(name).expect("a user id")
}

fn roles(names: &[&str]) -> BTreeSet<GroupRole> {
    names
        .iter()
        .map(|name| GroupRole::parse(*name).expect("a role"))
        .collect()
}

fn named(name: &str, carries: &[&str]) -> NewGroup {
    NewGroup {
        id: group(name),
        description: format!("the {name} group"),
        roles: roles(carries),
    }
}

async fn made(storage: &Storage, at: &str, name: &str, carries: &[&str]) {
    let created = storage
        .groups
        .create(&tenant(at), &named(name, carries), NOW)
        .await
        .expect("answered");
    assert!(
        matches!(created, GroupCreated::Created(_)),
        "{name}: {created:?}"
    );
}

async fn member_ids(storage: &Storage, at: &str, of: &str) -> Vec<String> {
    storage
        .groups
        .members(&tenant(at), &group(of), None, 10)
        .await
        .expect("listed")
        .into_iter()
        .map(|membership| membership.user.as_str().to_owned())
        .collect()
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_group_is_made_once_carries_its_roles_and_holds_its_members() {
    let storage = fresh(&tenant("acme"), 2).await;
    made(&storage, "acme", "staff", &["reader"]).await;
    made(&storage, "acme", "admins", &["reader", "writer"]).await;
    let again = storage
        .groups
        .create(&tenant("acme"), &named("staff", &[]), NOW)
        .await
        .expect("answered");
    assert_eq!(again, GroupCreated::Taken);

    let page = storage
        .groups
        .page(&tenant("acme"), None, 1)
        .await
        .expect("a page");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].id, group("admins"));
    let rest = storage
        .groups
        .page(&tenant("acme"), Some(&group("admins")), 10)
        .await
        .expect("a page");
    assert_eq!(
        rest.iter()
            .map(|found| found.id.clone())
            .collect::<Vec<_>>(),
        [group("staff")]
    );

    assert!(
        storage
            .groups
            .set_roles(
                &tenant("acme"),
                &group("staff"),
                &roles(&["auditor", "reader"])
            )
            .await
            .expect("set")
    );
    let staff = storage
        .groups
        .find(&tenant("acme"), &group("staff"))
        .await
        .expect("answered")
        .expect("found");
    assert_eq!(staff.roles, roles(&["auditor", "reader"]));
    assert!(
        !storage
            .groups
            .set_roles(&tenant("acme"), &group("nobody"), &roles(&["reader"]))
            .await
            .expect("answered"),
        "the roles of a group that is not there"
    );
    assert!(
        storage
            .groups
            .find(&tenant("acme"), &group("nobody"))
            .await
            .expect("answered")
            .is_none(),
        "setting roles made no group"
    );

    for (who, into) in [
        ("user-1", "staff"),
        ("user-2", "staff"),
        ("user-1", "admins"),
    ] {
        let joined = storage
            .groups
            .join(&tenant("acme"), &group(into), &user(who), "operator-1", NOW)
            .await
            .expect("answered");
        assert_eq!(joined, Joined::Added, "{who} into {into}");
    }
    let repeated = storage
        .groups
        .join(
            &tenant("acme"),
            &group("staff"),
            &user("user-1"),
            "operator-1",
            NOW,
        )
        .await
        .expect("answered");
    assert_eq!(repeated, Joined::Added, "joining twice is one membership");
    assert_eq!(
        member_ids(&storage, "acme", "staff").await,
        ["user-1", "user-2"]
    );
    let after = storage
        .groups
        .members(&tenant("acme"), &group("staff"), Some(&user("user-1")), 10)
        .await
        .expect("listed");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].user, user("user-2"));
    assert_eq!(after[0].added_by, "operator-1");

    let of_user = storage
        .groups
        .groups_of(&tenant("acme"), &user("user-1"))
        .await
        .expect("read");
    assert_eq!(
        of_user
            .iter()
            .map(|found| found.id.clone())
            .collect::<Vec<_>>(),
        [group("admins"), group("staff")]
    );

    let nowhere = storage
        .groups
        .join(
            &tenant("acme"),
            &group("nobody"),
            &user("user-1"),
            "operator-1",
            NOW,
        )
        .await
        .expect("answered");
    assert_eq!(nowhere, Joined::NoSuchGroup);
    assert!(
        member_ids(&storage, "acme", "nobody").await.is_empty(),
        "no membership without its group"
    );

    assert!(
        storage
            .groups
            .leave(&tenant("acme"), &group("staff"), &user("user-2"))
            .await
            .expect("answered")
    );
    assert!(
        !storage
            .groups
            .leave(&tenant("acme"), &group("staff"), &user("user-2"))
            .await
            .expect("answered"),
        "leaving twice finds nothing"
    );
    assert_eq!(member_ids(&storage, "acme", "staff").await, ["user-1"]);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_deleted_group_takes_its_memberships_and_another_company_never_sees_it() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    made(&storage, "acme", "staff", &["reader"]).await;
    made(&storage, "globex", "staff", &["writer"]).await;
    for at in ["acme", "globex"] {
        storage
            .groups
            .join(
                &tenant(at),
                &group("staff"),
                &user("user-1"),
                "operator-1",
                NOW,
            )
            .await
            .expect("answered");
    }

    assert!(
        storage
            .groups
            .delete(&tenant("acme"), &group("staff"))
            .await
            .expect("answered")
    );
    assert!(
        !storage
            .groups
            .delete(&tenant("acme"), &group("staff"))
            .await
            .expect("answered"),
        "deleting twice finds nothing"
    );
    made(&storage, "acme", "staff", &[]).await;
    assert!(
        member_ids(&storage, "acme", "staff").await.is_empty(),
        "a group made again under the id inherits no member"
    );
    assert!(
        storage
            .groups
            .groups_of(&tenant("acme"), &user("user-1"))
            .await
            .expect("read")
            .is_empty()
    );

    let elsewhere = storage
        .groups
        .find(&tenant("globex"), &group("staff"))
        .await
        .expect("answered")
        .expect("globex keeps its own group");
    assert_eq!(elsewhere.roles, roles(&["writer"]));
    assert_eq!(member_ids(&storage, "globex", "staff").await, ["user-1"]);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_user_in_as_many_groups_as_a_claim_carries_joins_no_more() {
    use tessari_oauth_constants::GROUPS_PER_USER_MAX;

    let storage = fresh(&tenant("acme"), 4).await;
    for number in 0..=GROUPS_PER_USER_MAX {
        let name = format!("g{number:03}");
        made(&storage, "acme", &name, &[]).await;
        let joined = storage
            .groups
            .join(
                &tenant("acme"),
                &group(&name),
                &user("user-1"),
                "operator-1",
                NOW,
            )
            .await
            .expect("answered");
        let expected = if number < GROUPS_PER_USER_MAX {
            Joined::Added
        } else {
            Joined::TooManyGroups
        };
        assert_eq!(joined, expected, "{name}");
    }
    let again = storage
        .groups
        .join(
            &tenant("acme"),
            &group("g000"),
            &user("user-1"),
            "operator-1",
            NOW,
        )
        .await
        .expect("answered");
    assert_eq!(again, Joined::Added, "a group already held is held again");
    let held = storage
        .groups
        .groups_of(&tenant("acme"), &user("user-1"))
        .await
        .expect("read");
    assert_eq!(
        held.len(),
        usize::try_from(GROUPS_PER_USER_MAX).expect("fits")
    );
}
