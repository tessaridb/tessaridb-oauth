//! A tenant's pairwise subjects: one salt per tenant, made once even when the first requests arrive together, kept
//! sealed, and opening only for its own tenant.

use std::sync::Arc;

use tessari_oauth_test_support::fresh_kek;
use tessari_oauth_types::{ClientId, TenantId, Timestamp, UserId};
use tokio::sync::Barrier;

use crate::fresh;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn client(id: &str) -> ClientId {
    ClientId::parse(id).expect("a client id")
}

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

fn user() -> UserId {
    UserId::parse("user-7").expect("a user id")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_subject_is_stable_for_its_client_and_differs_across_clients_and_tenants() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    let kek = fresh_kek().expect("a key-encryption key");
    let subject = |tenant_name: &'static str, client_id: &'static str| {
        let storage = storage.clone();
        let kek = &kek;
        async move {
            storage
                .subjects
                .pairwise(&tenant(tenant_name), kek, &client(client_id), &user(), NOW)
                .await
                .expect("a subject")
        }
    };
    let first = subject("acme", "svc-1").await;
    assert_eq!(first, subject("acme", "svc-1").await, "stable");
    assert_ne!(first, subject("acme", "svc-2").await, "per client");
    assert_ne!(first, subject("globex", "svc-1").await, "per tenant");
    assert!(!first.contains("user-7"), "opaque");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_first_requests_agree_on_one_salt() {
    let storage = fresh(&tenant("acme"), 8).await;
    let kek = Arc::new(fresh_kek().expect("a key-encryption key"));
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (storage, kek, barrier) = (storage.clone(), Arc::clone(&kek), Arc::clone(&barrier));
        tasks.spawn(async move {
            barrier.wait().await;
            storage
                .subjects
                .pairwise(&tenant("acme"), &kek, &client("svc-1"), &user(), NOW)
                .await
        });
    }
    let mut subjects = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        subjects.push(joined.expect("joined").expect("a subject"));
    }
    assert_eq!(subjects.len(), 8);
    assert!(
        subjects.iter().all(|subject| *subject == subjects[0]),
        "{subjects:?}"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_salt_made_under_another_key_does_not_open() {
    let storage = fresh(&tenant("acme"), 2).await;
    let made_with = fresh_kek().expect("a key-encryption key");
    storage
        .subjects
        .pairwise(&tenant("acme"), &made_with, &client("svc-1"), &user(), NOW)
        .await
        .expect("a subject");
    let path = std::env::temp_dir().join(tessari_oauth_test_support::unique("kek-other"));
    std::fs::write(&path, [9_u8; 32]).expect("written");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("owner-only");
    let other = tessari_oauth_infrastructure::custody::Kek::load(&path).expect("another key");
    std::fs::remove_file(&path).expect("removed");
    let refused = storage
        .subjects
        .pairwise(&tenant("acme"), &other, &client("svc-1"), &user(), NOW)
        .await;
    assert!(
        matches!(
            &refused,
            Err(tessari_oauth_storage::Error::Store(
                tessari_oauth_infrastructure::Error::Custody { .. }
            ))
        ),
        "{refused:?}"
    );
}
