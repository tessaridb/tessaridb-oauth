//! A refresh token rotates once; a spent token coming back revokes its whole family; nothing else changes a family.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_constants::{REFRESH_ABSOLUTE_TTL_SECS, REFRESH_IDLE_TTL_SECS};
use tessari_oauth_storage::refresh::{RefreshGrant, Rotation, RotationRefusal};
use tessari_oauth_types::{
    ClientId, RefreshToken, Resource, ScopeSet, TenantId, Timestamp, UserId,
};
use tokio::sync::Barrier;

use crate::fresh;

const START: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

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
        resources: ["https://api.example.com/"]
            .iter()
            .map(|uri| Resource::parse(*uri).expect("a resource"))
            .collect::<BTreeSet<_>>(),
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
async fn each_token_rotates_once_into_a_successor_carrying_the_same_grant() {
    let storage = fresh(&tenant(), 2).await;
    let refresh = &storage.refresh;
    refresh
        .start(&token("a"), &grant(), "family-a", at(START))
        .await
        .expect("started");

    let first = refresh
        .rotate(
            &tenant(),
            &token("a"),
            &token("b"),
            &portal(),
            at(START + 10),
        )
        .await;
    assert_eq!(first.expect("answered"), Rotation::Rotated(grant()));
    let second = refresh
        .rotate(
            &tenant(),
            &token("b"),
            &token("c"),
            &portal(),
            at(START + 20),
        )
        .await;
    assert_eq!(
        second.expect("answered"),
        Rotation::Rotated(grant()),
        "the successor rotates in turn"
    );
    let unknown = refresh
        .rotate(
            &tenant(),
            &token("never"),
            &token("x"),
            &portal(),
            at(START + 30),
        )
        .await;
    assert_eq!(
        unknown.expect("answered"),
        Rotation::Refused(RotationRefusal::Unknown)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_spent_token_presented_again_revokes_the_whole_family() {
    let storage = fresh(&tenant(), 2).await;
    let refresh = &storage.refresh;
    refresh
        .start(&token("a"), &grant(), "family-a", at(START))
        .await
        .expect("started");
    refresh
        .rotate(
            &tenant(),
            &token("a"),
            &token("b"),
            &portal(),
            at(START + 10),
        )
        .await
        .expect("rotated");

    let replay = refresh
        .rotate(
            &tenant(),
            &token("a"),
            &token("x"),
            &portal(),
            at(START + 20),
        )
        .await;
    assert_eq!(
        replay.expect("answered"),
        Rotation::Reused(grant()),
        "the spent token is a reuse"
    );
    let successor = refresh
        .rotate(
            &tenant(),
            &token("b"),
            &token("c"),
            &portal(),
            at(START + 30),
        )
        .await;
    assert_eq!(
        successor.expect("answered"),
        Rotation::Refused(RotationRefusal::FamilyRevoked),
        "the other chain dies with the family"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_token_of_another_client_is_refused_and_stays_usable_by_its_own() {
    let storage = fresh(&tenant(), 2).await;
    let refresh = &storage.refresh;
    let other = ClientId::parse("other-app").expect("a client id");
    refresh
        .start(&token("a"), &grant(), "family-a", at(START))
        .await
        .expect("started");

    let foreign = refresh
        .rotate(&tenant(), &token("a"), &token("x"), &other, at(START + 10))
        .await;
    assert_eq!(
        foreign.expect("answered"),
        Rotation::Refused(RotationRefusal::OtherClient)
    );
    let own = refresh
        .rotate(
            &tenant(),
            &token("a"),
            &token("b"),
            &portal(),
            at(START + 20),
        )
        .await;
    assert_eq!(
        own.expect("answered"),
        Rotation::Rotated(grant()),
        "nothing was spent by the refusal"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_token_unused_past_its_idle_bound_or_a_family_past_its_absolute_bound_does_not_rotate() {
    let storage = fresh(&tenant(), 2).await;
    let refresh = &storage.refresh;
    refresh
        .start(&token("idle"), &grant(), "family-idle", at(START))
        .await
        .expect("started");
    let idle = refresh
        .rotate(
            &tenant(),
            &token("idle"),
            &token("x"),
            &portal(),
            at(START + REFRESH_IDLE_TTL_SECS),
        )
        .await;
    assert_eq!(
        idle.expect("answered"),
        Rotation::Refused(RotationRefusal::Expired),
        "idle bound"
    );

    // Used every 13 days, a family still ends at its absolute bound.
    refresh
        .start(&token("a"), &grant(), "family-a", at(START))
        .await
        .expect("started");
    for (from, to, day) in [("a", "b", 13), ("b", "c", 26)] {
        let used = refresh
            .rotate(
                &tenant(),
                &token(from),
                &token(to),
                &portal(),
                at(START + day * DAY),
            )
            .await;
        assert_eq!(
            used.expect("answered"),
            Rotation::Rotated(grant()),
            "day {day}"
        );
    }
    let past = refresh
        .rotate(
            &tenant(),
            &token("c"),
            &token("d"),
            &portal(),
            at(START + REFRESH_ABSOLUTE_TTL_SECS),
        )
        .await;
    assert_eq!(
        past.expect("answered"),
        Rotation::Refused(RotationRefusal::Expired),
        "absolute bound"
    );
}

/// Sixteen rotations of one token at once, twenty rounds over: one rotates, the others are reuse, the family is gone.
/// A loser that reads the family after another loser revoked it is refused as revoked, which is the same verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_rotations_of_one_token_rotate_once_and_revoke_the_family() {
    const CONTENDERS: usize = 16;
    const ROUNDS: usize = 20;
    let storage = fresh(&tenant(), CONTENDERS).await;
    for round in 0..ROUNDS {
        let first = token(&format!("round-{round}"));
        storage
            .refresh
            .start(&first, &grant(), &first.digest(), at(START))
            .await
            .expect("started");
        let start = Arc::new(Barrier::new(CONTENDERS));
        let mut contenders = Vec::with_capacity(CONTENDERS);
        for slot in 0..CONTENDERS {
            let (storage, first, start) = (storage.clone(), first.clone(), Arc::clone(&start));
            let next = token(&format!("round-{round}-next-{slot}"));
            contenders.push(tokio::spawn(async move {
                start.wait().await;
                let outcome = storage
                    .refresh
                    .rotate(&tenant(), &first, &next, &portal(), at(START + 10))
                    .await;
                (next, outcome)
            }));
        }
        let mut winners = Vec::new();
        let mut reuses = 0_usize;
        let mut revoked = 0_usize;
        for contender in contenders {
            let (next, outcome) = contender.await.expect("joined");
            match outcome.expect("answered") {
                Rotation::Rotated(_) => winners.push(next),
                Rotation::Reused(_) => reuses += 1,
                Rotation::Refused(RotationRefusal::FamilyRevoked) => revoked += 1,
                Rotation::Refused(refusal) => panic!("round {round}: refused {refusal:?}"),
            }
        }
        assert_eq!(winners.len(), 1, "round {round}: exactly one rotation");
        assert!(reuses >= 1, "round {round}: the reuse was detected");
        assert_eq!(
            reuses + revoked,
            CONTENDERS - 1,
            "round {round}: every loser is a reuse or meets the revoked family"
        );
        let after = storage
            .refresh
            .rotate(
                &tenant(),
                &winners[0],
                &token("late"),
                &portal(),
                at(START + 20),
            )
            .await;
        assert_eq!(
            after.expect("answered"),
            Rotation::Refused(RotationRefusal::FamilyRevoked),
            "round {round}: the reuse revoked the family the winner's successor belongs to"
        );
    }
}
