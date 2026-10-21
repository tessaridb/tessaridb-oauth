//! A replayed code takes the refresh family started from it with it — and when the replay arrives first, no family
//! can be started from that code at all.

use std::collections::BTreeSet;

use tessari_oauth_storage::refresh::{RefreshGrant, Rotation, RotationRefusal};
use tessari_oauth_types::{
    ClientId, ErrorCategory, RefreshToken, Resource, ScopeSet, TenantId, Timestamp, UserId,
};

use crate::fresh;

const START: u64 = 1_800_000_000;

fn tenant() -> TenantId {
    TenantId::parse("acme-eu").expect("a tenant id")
}

fn portal() -> ClientId {
    ClientId::parse("portal").expect("a client id")
}

fn grant() -> RefreshGrant {
    RefreshGrant {
        tenant: tenant(),
        user: UserId::parse("user-7").expect("a user id"),
        client_id: portal(),
        scopes: ScopeSet::parse("openid offline_access").expect("scopes"),
        resources: BTreeSet::from([
            Resource::parse("https://api.example.com/").expect("a resource")
        ]),
    }
}

fn token(name: &str) -> RefreshToken {
    RefreshToken::from_secret(format!("refresh-secret-{name}"))
}

fn at(seconds: u64) -> Timestamp {
    Timestamp::from_unix_secs(seconds)
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_replayed_code_revokes_the_family_started_from_it() {
    let storage = fresh(&tenant(), 2).await;
    let refresh = &storage.refresh;
    refresh
        .start(&token("a"), &grant(), "code-1", at(START))
        .await
        .expect("started");
    refresh
        .revoke_for_replay(&grant(), "code-1", at(START + 1))
        .await
        .expect("revoked");
    let rotation = refresh
        .rotate(
            &tenant(),
            &token("a"),
            &token("b"),
            &portal(),
            at(START + 2),
        )
        .await
        .expect("answered");
    assert_eq!(rotation, Rotation::Refused(RotationRefusal::FamilyRevoked));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_replay_before_the_family_starts_leaves_no_family_to_start() {
    let storage = fresh(&tenant(), 2).await;
    let refresh = &storage.refresh;
    refresh
        .revoke_for_replay(&grant(), "code-2", at(START))
        .await
        .expect("a tombstone");
    let started = refresh
        .start(&token("c"), &grant(), "code-2", at(START + 1))
        .await;
    assert!(
        started.is_err_and(|error| error.category() == ErrorCategory::Conflict),
        "the winner cannot start a family from a replayed code"
    );
    let rotation = refresh
        .rotate(
            &tenant(),
            &token("c"),
            &token("d"),
            &portal(),
            at(START + 2),
        )
        .await
        .expect("answered");
    assert_eq!(rotation, Rotation::Refused(RotationRefusal::Unknown));
    refresh
        .revoke_for_replay(&grant(), "code-2", at(START + 3))
        .await
        .expect("a second replay changes nothing");
}
