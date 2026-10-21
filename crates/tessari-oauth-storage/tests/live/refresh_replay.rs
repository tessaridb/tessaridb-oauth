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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_replays_and_a_start_all_answer_and_leave_the_family_revoked() {
    let storage = std::sync::Arc::new(fresh(&tenant(), 9).await);
    for round in 0..20 {
        let family = format!("code-race-{round}");
        let mut racers = tokio::task::JoinSet::new();
        for replay in 0..8 {
            let (storage, family) = (std::sync::Arc::clone(&storage), family.clone());
            racers.spawn(async move {
                let replayed = storage
                    .refresh
                    .revoke_for_replay(&grant(), &family, at(START + replay))
                    .await;
                (false, replayed)
            });
        }
        let (starter, family_id) = (std::sync::Arc::clone(&storage), family.clone());
        racers.spawn(async move {
            let started = starter
                .refresh
                .start(&token(&family_id), &grant(), &family_id, at(START))
                .await;
            (true, started)
        });
        for (is_start, outcome) in racers.join_all().await {
            match outcome {
                Ok(()) => {}
                // Only the start may lose, and only to a family a replay already recorded.
                Err(error) if is_start && error.category() == ErrorCategory::Conflict => {}
                Err(error) => panic!(
                    "round {round}: {} failed: {error:?}",
                    if is_start { "start" } else { "replay" }
                ),
            }
        }
        let rotation = storage
            .refresh
            .rotate(
                &tenant(),
                &token(&family),
                &token("next"),
                &portal(),
                at(START + 9),
            )
            .await
            .expect("answered");
        assert!(
            matches!(
                rotation,
                Rotation::Refused(RotationRefusal::FamilyRevoked | RotationRefusal::Unknown)
            ),
            "round {round}: {rotation:?}"
        );
    }
}
