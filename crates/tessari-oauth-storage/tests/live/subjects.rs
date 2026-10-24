//! A tenant's pairwise subjects: one salt per tenant, made once even when the first requests arrive together, kept
//! sealed, and opening only for its own tenant.

use std::sync::Arc;

use tessari_oauth_core::subject::SubjectSector;
use tessari_oauth_test_support::fresh_kek;
use tessari_oauth_types::{ClientId, Sector, TenantId, Timestamp, UserId};
use tokio::sync::Barrier;

use crate::fresh;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn client(id: &str) -> SubjectSector {
    SubjectSector::Client(ClientId::parse(id).expect("a client id"))
}

fn sector(name: &str) -> SubjectSector {
    SubjectSector::Named(Sector::parse(name).expect("a sector"))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_first_requests_agree_on_one_salt() {
    let storage = fresh(&tenant("acme"), 8).await;
    let kek = Arc::new(fresh_kek().expect("a key-encryption key"));
    // Each round is a tenant with no salt yet, so every round races the first write again.
    for round in 0..10 {
        let name = format!("race-{round}");
        storage
            .tenants
            .provision(&tenant(&name))
            .await
            .expect("provisioned");
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (storage, kek, barrier, name) = (
                storage.clone(),
                Arc::clone(&kek),
                Arc::clone(&barrier),
                name.clone(),
            );
            tasks.spawn(async move {
                barrier.wait().await;
                storage
                    .subjects
                    .pairwise(&tenant(&name), &kek, &client("svc-1"), &user(), NOW)
                    .await
            });
        }
        let mut subjects = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let subject = joined.expect("joined");
            subjects.push(subject.unwrap_or_else(|error| panic!("round {round}: {error:?}")));
        }
        assert_eq!(subjects.len(), 8);
        assert!(
            subjects.iter().all(|subject| *subject == subjects[0]),
            "round {round}: {subjects:?}"
        );
    }
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

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_derived_subject_leads_back_to_its_user_at_its_own_client_only() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    let kek = fresh_kek().expect("a key-encryption key");
    let subject = storage
        .subjects
        .pairwise(&tenant("acme"), &kek, &client("svc-1"), &user(), NOW)
        .await
        .expect("a subject");
    let again = storage
        .subjects
        .pairwise(&tenant("acme"), &kek, &client("svc-1"), &user(), NOW)
        .await
        .expect("the same subject, recorded once");
    assert_eq!(again, subject);
    assert_eq!(
        storage
            .subjects
            .user_of(&tenant("acme"), &client("svc-1"), &subject)
            .await
            .expect("answered"),
        Some(user())
    );
    assert_eq!(
        storage
            .subjects
            .user_of(&tenant("acme"), &client("svc-2"), &subject)
            .await
            .expect("answered"),
        None,
        "a subject presented by another client leads nowhere"
    );
    assert_eq!(
        storage
            .subjects
            .user_of(&tenant("globex"), &client("svc-1"), &subject)
            .await
            .expect("answered"),
        None,
        "nor in another company"
    );
    assert_eq!(
        storage
            .subjects
            .user_of(&tenant("acme"), &client("svc-1"), "never-derived")
            .await
            .expect("answered"),
        None
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_named_sector_is_one_subject_and_leads_back_to_its_user() {
    let storage = fresh(&tenant("acme"), 1).await;
    let kek = fresh_kek().expect("a key-encryption key");
    let subject = storage
        .subjects
        .pairwise(&tenant("acme"), &kek, &sector("cloud"), &user(), NOW)
        .await
        .expect("a subject");
    assert_eq!(
        storage
            .subjects
            .user_of(&tenant("acme"), &sector("cloud"), &subject)
            .await
            .expect("answered"),
        Some(user()),
        "found again in its sector"
    );
    assert_eq!(
        storage
            .subjects
            .user_of(&tenant("acme"), &client("cloud"), &subject)
            .await
            .expect("answered"),
        None,
        "a client named like the sector does not reach it"
    );
    assert_ne!(
        subject,
        storage
            .subjects
            .pairwise(&tenant("acme"), &kek, &client("cloud"), &user(), NOW)
            .await
            .expect("a subject"),
        "nor shares its subject"
    );
}
