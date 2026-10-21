//! A client assertion or a DPoP proof is spent once per tenant: its `jti` under its client or key is a record that
//! frees itself.

use std::future::Future;
use std::sync::Arc;

use tessari_oauth_core::assertion::AssertionUse;
use tessari_oauth_core::dpop::ProofUse;
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::replay::Spent;
use tessari_oauth_types::{ClientId, KeyThumbprint, TenantId, Timestamp};
use tokio::sync::Barrier;

use crate::fresh;

const NOW: u64 = 1_800_000_000;
/// RFC 9449 §6 and RFC 8037 §A.3 thumbprints: two keys.
const KEY: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
const OTHER_KEY: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

fn tenant() -> TenantId {
    TenantId::parse("acme-eu").expect("a tenant id")
}

fn now() -> Timestamp {
    Timestamp::from_unix_secs(NOW)
}

fn assertion(client: &str, jti: &str) -> AssertionUse {
    AssertionUse {
        client_id: ClientId::parse(client).expect("a client id"),
        jti: jti.to_owned(),
        expires_at: Timestamp::from_unix_secs(NOW + 60),
    }
}

fn proof(key: &str, jti: &str) -> ProofUse {
    ProofUse {
        thumbprint: KeyThumbprint::parse(key).expect("a thumbprint"),
        jti: jti.to_owned(),
        expires_at: Timestamp::from_unix_secs(NOW + 60),
    }
}

async fn spend_assertion(storage: &Storage, used: &AssertionUse) -> Spent {
    storage
        .replay
        .spend_assertion(&tenant(), used, now())
        .await
        .expect("answered")
}

async fn spend_proof(storage: &Storage, used: &ProofUse) -> Spent {
    storage
        .replay
        .spend_proof(&tenant(), used, now())
        .await
        .expect("answered")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_assertion_is_spent_once_and_its_second_presentation_is_a_replay() {
    let storage = fresh(&tenant(), 2).await;
    assert_eq!(
        spend_assertion(&storage, &assertion("svc", "a-1")).await,
        Spent::Fresh
    );
    assert_eq!(
        spend_assertion(&storage, &assertion("svc", "a-1")).await,
        Spent::Replayed
    );
    assert_eq!(
        spend_assertion(&storage, &assertion("other", "a-1")).await,
        Spent::Fresh,
        "a jti is per client"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_id_with_a_space_cannot_spend_another_clients_jti() {
    let storage = fresh(&tenant(), 2).await;
    for used in [assertion("a b", "c"), assertion("a", "b c")] {
        assert_eq!(
            spend_assertion(&storage, &used).await,
            Spent::Fresh,
            "{used:?}"
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_proof_is_spent_once_per_key_and_never_collides_with_an_assertion() {
    let storage = fresh(&tenant(), 2).await;
    assert_eq!(
        spend_proof(&storage, &proof(KEY, "p-1")).await,
        Spent::Fresh
    );
    assert_eq!(
        spend_proof(&storage, &proof(KEY, "p-1")).await,
        Spent::Replayed
    );
    assert_eq!(
        spend_proof(&storage, &proof(OTHER_KEY, "p-1")).await,
        Spent::Fresh,
        "a jti is per key"
    );
    // An assertion whose client id is the thumbprint and whose jti is the proof's: a different record.
    assert_eq!(
        spend_assertion(&storage, &assertion(KEY, "p-1")).await,
        Spent::Fresh
    );
}

/// Sixteen presentations at once, twenty rounds over, of whatever `spend` spends: exactly one is Fresh.
async fn exactly_one_of_sixteen<F, Spend>(name: &str, spend: F)
where
    F: Fn(Storage, usize) -> Spend + Copy + Send + 'static,
    Spend: Future<Output = Spent> + Send + 'static,
{
    const CONTENDERS: usize = 16;
    const ROUNDS: usize = 20;
    let storage = fresh(&tenant(), CONTENDERS).await;
    for round in 0..ROUNDS {
        let start = Arc::new(Barrier::new(CONTENDERS));
        let mut contenders = Vec::with_capacity(CONTENDERS);
        for _ in 0..CONTENDERS {
            let (storage, start) = (storage.clone(), Arc::clone(&start));
            contenders.push(tokio::spawn(async move {
                start.wait().await;
                spend(storage, round).await
            }));
        }
        let mut fresh_spends = 0_usize;
        for contender in contenders {
            if contender.await.expect("joined") == Spent::Fresh {
                fresh_spends = fresh_spends.saturating_add(1);
            }
        }
        assert_eq!(fresh_spends, 1, "{name} round {round}: exactly one spend");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_presentations_of_one_assertion_spend_it_once() {
    exactly_one_of_sixteen("assertion", |storage, round| async move {
        spend_assertion(&storage, &assertion("svc", &format!("round-{round}"))).await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_presentations_of_one_proof_spend_it_once() {
    exactly_one_of_sixteen("proof", |storage, round| async move {
        spend_proof(&storage, &proof(KEY, &format!("round-{round}"))).await
    })
    .await;
}
