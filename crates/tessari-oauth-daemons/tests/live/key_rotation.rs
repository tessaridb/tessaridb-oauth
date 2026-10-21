//! The rotation daemon applies the rotation rule to each tenant: a key when there is none, a successor when the
//! signing key is due, a retirement for a withdrawn key — every key sealed, its public half beside it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tessari_oauth_constants::{JWKS_MAX_AGE_SECS, SIGNING_KEY_LIFETIME_SECS};
use tessari_oauth_daemons::{Daemon, KeyRotation};
use tessari_oauth_infrastructure::custody::{Kek, SigningKey};
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::keys::StoredKey;
use tessari_oauth_types::{Algorithm, TenantId, Timestamp};

use crate::{fresh_kek, storage};

const START: u64 = 1_800_000_000;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

/// The daemon over `storage` for `tenants`, at the time `clock` holds.
fn daemon(
    storage: &Storage,
    kek: &Arc<Kek>,
    tenants: &[TenantId],
    clock: &Arc<AtomicU64>,
) -> KeyRotation {
    let clock = Arc::clone(clock);
    KeyRotation {
        keys: Arc::clone(&storage.keys),
        kek: Arc::clone(kek),
        tenants: tenants.to_vec(),
        algorithm: Algorithm::Es256,
        clock: Arc::new(move || Timestamp::from_unix_secs(clock.load(Ordering::Relaxed))),
        interval: Duration::from_secs(60),
        timeout: Duration::from_secs(30),
    }
}

async fn provisioned(storage: &Storage, tenants: &[TenantId]) {
    for tenant in tenants {
        storage
            .tenants
            .provision(tenant)
            .await
            .expect("tenant provisioned");
    }
}

async fn live(storage: &Storage, tenant: &TenantId) -> Vec<StoredKey> {
    storage.keys.live(tenant).await.expect("keys listed")
}

/// The sealed key opens for its tenant and `kid`, and is the key its public half describes.
fn opens(kek: &Kek, tenant: &TenantId, key: &StoredKey) {
    let pkcs8 = kek
        .unseal(tenant, key.kid.as_str(), &key.sealed)
        .expect("the sealed key opens for its tenant and kid");
    let opened = SigningKey::from_pkcs8(key.algorithm, &pkcs8).expect("a PKCS#8 key");
    assert_eq!(opened.kid(), &key.kid);
    assert_eq!(opened.public_jwk().expect("a JWK"), key.public_jwk);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_tenant_with_no_key_gets_one_and_only_one() {
    let (storage, kek) = (storage(), fresh_kek());
    let acme = tenant("acme-eu");
    provisioned(&storage, std::slice::from_ref(&acme)).await;
    let clock = Arc::new(AtomicU64::new(START));
    let rotation = daemon(&storage, &kek, std::slice::from_ref(&acme), &clock);

    rotation.run_once().await.expect("the run succeeds");
    let keys = live(&storage, &acme).await;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].algorithm, Algorithm::Es256);
    assert_eq!(keys[0].created_at, Timestamp::from_unix_secs(START));
    opens(&kek, &acme, &keys[0]);

    rotation.run_once().await.expect("the run succeeds");
    assert_eq!(live(&storage, &acme).await, keys, "nothing was due");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_successor_is_made_when_the_signing_key_is_due() {
    let (storage, kek) = (storage(), fresh_kek());
    let acme = tenant("acme-eu");
    provisioned(&storage, std::slice::from_ref(&acme)).await;
    let clock = Arc::new(AtomicU64::new(START));
    let rotation = daemon(&storage, &kek, std::slice::from_ref(&acme), &clock);
    rotation.run_once().await.expect("the run succeeds");

    let due = START + SIGNING_KEY_LIFETIME_SECS - JWKS_MAX_AGE_SECS;
    clock.store(due - 1, Ordering::Relaxed);
    rotation.run_once().await.expect("the run succeeds");
    assert_eq!(
        live(&storage, &acme).await.len(),
        1,
        "not due a second early"
    );

    clock.store(due, Ordering::Relaxed);
    rotation.run_once().await.expect("the run succeeds");
    let keys = live(&storage, &acme).await;
    assert_eq!(
        keys.len(),
        2,
        "the successor is published beside its predecessor"
    );
    assert_eq!(keys[1].created_at, Timestamp::from_unix_secs(due));
    opens(&kek, &acme, &keys[1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_compromised_key_is_retired_and_replaced() {
    let (storage, kek) = (storage(), fresh_kek());
    let acme = tenant("acme-eu");
    provisioned(&storage, std::slice::from_ref(&acme)).await;
    let clock = Arc::new(AtomicU64::new(START));
    let rotation = daemon(&storage, &kek, std::slice::from_ref(&acme), &clock);
    rotation.run_once().await.expect("the run succeeds");
    let burnt = live(&storage, &acme).await.remove(0).kid;
    storage
        .keys
        .compromise(&acme, &burnt)
        .await
        .expect("withdrawn");

    clock.store(START + 1, Ordering::Relaxed);
    rotation.run_once().await.expect("the run succeeds");
    let keys = live(&storage, &acme).await;
    assert_eq!(keys.len(), 1, "the withdrawn key is retired");
    assert_ne!(keys[0].kid, burnt);
    assert!(!keys[0].compromised);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_tenant_gets_its_own_key() {
    let (storage, kek) = (storage(), fresh_kek());
    let tenants: Vec<TenantId> = (0..10).map(|n| tenant(&format!("t{n}"))).collect();
    provisioned(&storage, &tenants).await;
    let clock = Arc::new(AtomicU64::new(START));
    daemon(&storage, &kek, &tenants, &clock)
        .run_once()
        .await
        .expect("the run succeeds");
    let mut kids = Vec::new();
    for tenant in &tenants {
        let keys = live(&storage, tenant).await;
        assert_eq!(keys.len(), 1, "{tenant:?}");
        opens(&kek, tenant, &keys[0]);
        kids.push(keys[0].kid.clone());
    }
    kids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    kids.dedup();
    assert_eq!(kids.len(), tenants.len(), "no two tenants share a key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_failing_tenant_is_named_and_the_others_still_rotate() {
    let (storage, kek) = (storage(), fresh_kek());
    let (ready, missing) = (tenant("ready"), tenant("never-provisioned"));
    provisioned(&storage, std::slice::from_ref(&ready)).await;
    let clock = Arc::new(AtomicU64::new(START));
    let failed = daemon(&storage, &kek, &[missing, ready.clone()], &clock)
        .run_once()
        .await
        .expect_err("one tenant has no store");
    let message = failed.to_string();
    assert!(message.contains("key-rotation"), "{message}");
    assert!(message.contains("1 of 2 tenants failed"), "{message}");
    assert!(message.contains("never-provisioned:"), "{message}");
    assert_eq!(
        live(&storage, &ready).await.len(),
        1,
        "the other tenant rotated"
    );
}
