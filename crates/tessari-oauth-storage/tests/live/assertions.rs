//! A client assertion is spent once per tenant: its `jti` under its client is a record that frees itself.

use std::sync::Arc;

use tessari_oauth_core::assertion::AssertionUse;
use tessari_oauth_storage::assertions::Spent;
use tessari_oauth_types::{ClientId, TenantId, Timestamp};
use tokio::sync::Barrier;

use crate::fresh;

const NOW: u64 = 1_800_000_000;

fn tenant() -> TenantId {
    TenantId::parse("acme-eu").expect("a tenant id")
}

fn used(client: &str, jti: &str) -> AssertionUse {
    AssertionUse {
        client_id: ClientId::parse(client).expect("a client id"),
        jti: jti.to_owned(),
        expires_at: Timestamp::from_unix_secs(NOW + 60),
    }
}

fn now() -> Timestamp {
    Timestamp::from_unix_secs(NOW)
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_assertion_is_spent_once_and_its_second_presentation_is_a_replay() {
    let storage = fresh(&tenant(), 2).await;
    let first = used("svc", "a-1");
    let spend = |assertion: AssertionUse| {
        let storage = storage.clone();
        async move {
            storage
                .assertions
                .spend(&tenant(), &assertion, now())
                .await
                .expect("answered")
        }
    };
    assert_eq!(spend(first.clone()).await, Spent::Fresh);
    assert_eq!(spend(first).await, Spent::Replayed);
    assert_eq!(
        spend(used("other", "a-1")).await,
        Spent::Fresh,
        "a jti is per client"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_id_with_a_space_cannot_spend_another_clients_jti() {
    let storage = fresh(&tenant(), 2).await;
    for assertion in [used("a b", "c"), used("a", "b c")] {
        assert_eq!(
            storage
                .assertions
                .spend(&tenant(), &assertion, now())
                .await
                .expect("answered"),
            Spent::Fresh,
            "{assertion:?}"
        );
    }
}

/// Sixteen presentations of one assertion at once, twenty rounds over: exactly one is spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_presentations_of_one_assertion_spend_it_once() {
    const CONTENDERS: usize = 16;
    const ROUNDS: usize = 20;
    let storage = fresh(&tenant(), CONTENDERS).await;
    for round in 0..ROUNDS {
        let assertion = used("svc", &format!("round-{round}"));
        let start = Arc::new(Barrier::new(CONTENDERS));
        let mut contenders = Vec::with_capacity(CONTENDERS);
        for _ in 0..CONTENDERS {
            let (storage, assertion, start) =
                (storage.clone(), assertion.clone(), Arc::clone(&start));
            contenders.push(tokio::spawn(async move {
                start.wait().await;
                storage.assertions.spend(&tenant(), &assertion, now()).await
            }));
        }
        let mut fresh_spends = 0_usize;
        for contender in contenders {
            if contender.await.expect("joined").expect("answered") == Spent::Fresh {
                fresh_spends += 1;
            }
        }
        assert_eq!(fresh_spends, 1, "round {round}: exactly one spend");
    }
}
