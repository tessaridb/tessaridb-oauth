use std::collections::BTreeSet;

use tessari_oauth_types::{GroupId, GroupRole};

use super::{GroupClaims, Place, group_claims, releases};

fn scopes(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn the_group_claims_are_released_at_userinfo_only_under_their_scope() {
    for claim in ["groups", "roles"] {
        assert!(releases(
            claim,
            Place::UserInfo,
            &scopes(&["openid", "groups"])
        ));
        assert!(
            !releases(claim, Place::UserInfo, &scopes(&["openid"])),
            "{claim}"
        );
        assert!(
            !releases(
                claim,
                Place::UserInfo,
                &scopes(&["openid", "groupsx", "group"])
            ),
            "{claim}: a scope is matched whole"
        );
    }
    assert!(
        !releases(
            "email",
            Place::UserInfo,
            &scopes(&["openid", "groups", "email"])
        ),
        "a claim the table does not name is never released"
    );
}

#[test]
fn the_name_claims_are_released_at_userinfo_only_under_profile() {
    for claim in ["name", "given_name", "family_name"] {
        assert!(
            releases(claim, Place::UserInfo, &scopes(&["openid", "profile"])),
            "{claim}"
        );
        assert!(
            !releases(claim, Place::UserInfo, &scopes(&["openid", "groups"])),
            "{claim}"
        );
    }
    for unlisted in ["picture", "birthdate", "locale", "nickname"] {
        assert!(
            !releases(unlisted, Place::UserInfo, &scopes(&["openid", "profile"])),
            "{unlisted}: `profile` releases the three names and nothing else"
        );
    }
}

#[test]
fn group_claims_name_each_group_and_role_once_in_order() {
    let id = |name: &str| GroupId::parse(name).expect("a group id");
    let roles = |names: &[&str]| -> BTreeSet<GroupRole> {
        names
            .iter()
            .map(|name| GroupRole::parse(*name).expect("a role"))
            .collect()
    };
    let (staff, admins, empty) = (id("staff"), id("admins"), id("empty"));
    let (staff_roles, admin_roles, none) =
        (roles(&["reader"]), roles(&["writer", "reader"]), roles(&[]));
    assert_eq!(
        group_claims([
            (&staff, &staff_roles),
            (&admins, &admin_roles),
            (&empty, &none)
        ]),
        GroupClaims {
            groups: scopes(&["admins", "empty", "staff"]),
            roles: scopes(&["reader", "writer"]),
        }
    );
    assert_eq!(
        group_claims(std::iter::empty()),
        GroupClaims {
            groups: Vec::new(),
            roles: Vec::new()
        }
    );
}
