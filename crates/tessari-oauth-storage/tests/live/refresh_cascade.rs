//! An account event revokes every standing refresh family it names — a user's, a client's, or one user's at one
//! client — and no other; a family already revoked keeps its reason and is not counted again.

use std::collections::BTreeSet;

use tessari_oauth_storage::Storage;
use tessari_oauth_storage::refresh::{Holder, RefreshGrant, Rotation, RotationRefusal};
use tessari_oauth_types::{
    ClientId, RefreshToken, Resource, ScopeSet, TenantId, Timestamp, UserId,
};

use crate::fresh;

const START: u64 = 1_800_000_000;

fn tenant() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn client(id: &str) -> ClientId {
    ClientId::parse(id).expect("a client id")
}

fn user(id: &str) -> UserId {
    UserId::parse(id).expect("a user id")
}

fn token(name: &str) -> RefreshToken {
    RefreshToken::from_secret(format!("refresh-secret-{name}"))
}

fn at(offset: u64) -> Timestamp {
    Timestamp::from_unix_secs(START.checked_add(offset).expect("a time within range"))
}

/// Families `f1` (user-7 at portal), `f2` (user-7 at studio), `f3` (user-8 at portal) standing, and `f4` (user-7 at
/// portal) already revoked; each started from the token of its own name.
async fn families() -> Storage {
    let storage = fresh(&tenant(), 2).await;
    for (name, holder, at_client) in [
        ("f1", "user-7", "portal"),
        ("f2", "user-7", "studio"),
        ("f3", "user-8", "portal"),
        ("f4", "user-7", "portal"),
    ] {
        let grant = RefreshGrant {
            tenant: tenant(),
            user: user(holder),
            client_id: client(at_client),
            scopes: ScopeSet::parse("api:read").expect("scopes"),
            resources: BTreeSet::from([
                Resource::parse("https://api.example.com/").expect("a resource")
            ]),
            bound_to: None,
        };
        storage
            .refresh
            .start(&token(name), &grant, &format!("family-{name}"), at(0))
            .await
            .expect("started");
    }
    storage
        .refresh
        .revoke(&tenant(), "family-f4", "reuse", at(1))
        .await
        .expect("revoked");
    storage
}

/// Whether the family started from `name`'s token at `at_client` still rotates.
async fn rotates(storage: &Storage, name: &str, at_client: &str) -> bool {
    let rotation = storage
        .refresh
        .rotate(
            &tenant(),
            &token(name),
            &token(&format!("{name}-next")),
            &client(at_client),
            at(10),
        )
        .await
        .expect("answered");
    match rotation {
        Rotation::Rotated(_) => true,
        Rotation::Refused(RotationRefusal::FamilyRevoked) => false,
        other => panic!("{name}: neither rotated nor revoked: {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_users_standing_families_are_revoked_at_every_client() {
    let storage = families().await;
    let holder = user("user-7");
    let revoked = storage
        .refresh
        .revoke_standing(&tenant(), &Holder::User(&holder), "password_changed", at(2))
        .await
        .expect("revoked");
    assert_eq!(revoked, 2, "f1 and f2; f4 was revoked already");
    assert!(!rotates(&storage, "f1", "portal").await, "f1");
    assert!(!rotates(&storage, "f2", "studio").await, "f2");
    assert!(
        rotates(&storage, "f3", "portal").await,
        "another user's family"
    );
    let again = storage
        .refresh
        .revoke_standing(&tenant(), &Holder::User(&holder), "password_changed", at(3))
        .await
        .expect("revoked");
    assert_eq!(again, 0, "nothing of user-7's stands any more");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_clients_standing_families_are_revoked_for_every_user() {
    let storage = families().await;
    let portal = client("portal");
    let revoked = storage
        .refresh
        .revoke_standing(
            &tenant(),
            &Holder::Client(&portal),
            "client_disabled",
            at(2),
        )
        .await
        .expect("revoked");
    assert_eq!(revoked, 2, "f1 and f3; f4 was revoked already");
    assert!(!rotates(&storage, "f1", "portal").await, "f1");
    assert!(!rotates(&storage, "f3", "portal").await, "f3");
    assert!(
        rotates(&storage, "f2", "studio").await,
        "another client's family"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn one_users_families_at_one_client_are_revoked_and_no_others() {
    let storage = families().await;
    let (holder, portal) = (user("user-7"), client("portal"));
    let revoked = storage
        .refresh
        .revoke_standing(
            &tenant(),
            &Holder::Grant {
                user: &holder,
                client: &portal,
            },
            "consent_withdrawn",
            at(2),
        )
        .await
        .expect("revoked");
    assert_eq!(revoked, 1, "f1; f4 was revoked already");
    assert!(!rotates(&storage, "f1", "portal").await, "f1");
    assert!(
        rotates(&storage, "f2", "studio").await,
        "the user at another client"
    );
    assert!(
        rotates(&storage, "f3", "portal").await,
        "another user at the client"
    );
}
