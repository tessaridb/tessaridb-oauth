//! Second factors: a one-time code secret is enrolled once, kept sealed and opens only for its own tenant and key;
//! a code's time step is accepted once even when eight requests carry it at once; recovery codes are replaced as a
//! set and each is spent once, and only by its owner.

use std::sync::Arc;

use tessari_oauth_infrastructure::custody::{recovery_codes, recovery_digest};
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::factors::Enrolled;
use tessari_oauth_test_support::fresh_kek;
use tessari_oauth_types::{ErrorCategory, TenantId, Timestamp, UserId};
use tokio::sync::Barrier;

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

const SECRET: &[u8] = b"12345678901234567890";

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn user(id: &str) -> UserId {
    UserId::parse(id).expect("a user id")
}

/// The digests of a freshly made set of recovery codes, with the codes themselves.
fn code_set() -> (Vec<String>, Vec<String>) {
    let codes = recovery_codes().expect("codes");
    let digests = codes
        .iter()
        .map(|code| recovery_digest(code).expect("a digest"))
        .collect();
    (codes, digests)
}

async fn enrolled(storage: &Storage, kek: &tessari_oauth_infrastructure::custody::Kek, id: &str) {
    assert_eq!(
        storage
            .factors
            .enroll_totp(&tenant("acme"), kek, &user(id), SECRET, NOW)
            .await,
        Ok(Enrolled::Created)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_secret_is_enrolled_once_and_opens_only_for_its_tenant_and_key() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    let kek = fresh_kek().expect("a key-encryption key");
    enrolled(&storage, &kek, "user-1").await;
    assert_eq!(
        storage
            .factors
            .enroll_totp(
                &tenant("acme"),
                &kek,
                &user("user-1"),
                b"another secret 01234",
                NOW
            )
            .await,
        Ok(Enrolled::AlreadyEnrolled)
    );
    let opened = storage
        .factors
        .totp(&tenant("acme"), &kek, &user("user-1"))
        .await
        .expect("read")
        .expect("a factor");
    assert_eq!(opened.secret.as_slice(), SECRET, "the first secret is kept");
    assert_eq!(opened.last_step, 0);
    assert_eq!(
        storage
            .factors
            .totp(&tenant("globex"), &kek, &user("user-1"))
            .await,
        Ok(None),
        "another tenant"
    );
    assert_eq!(
        storage
            .factors
            .totp(&tenant("acme"), &kek, &user("user-2"))
            .await,
        Ok(None),
        "another user"
    );
    let path = std::env::temp_dir().join(tessari_oauth_test_support::unique("kek-other"));
    std::fs::write(&path, [9_u8; 32]).expect("written");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("owner-only");
    let other = tessari_oauth_infrastructure::custody::Kek::load(&path).expect("another key");
    std::fs::remove_file(&path).expect("removed");
    let refused = storage
        .factors
        .totp(&tenant("acme"), &other, &user("user-1"))
        .await;
    assert!(
        matches!(
            &refused,
            Err(tessari_oauth_storage::Error::Store(
                tessari_oauth_infrastructure::Error::Custody { .. }
            ))
        ),
        "another key does not open it: {refused:?}"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_step_is_accepted_once_and_never_after_a_later_one() {
    let storage = fresh(&tenant("acme"), 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    enrolled(&storage, &kek, "user-1").await;
    let accept = |step: u64| {
        let storage = storage.clone();
        async move {
            storage
                .factors
                .accept_step(&tenant("acme"), &user("user-1"), step)
                .await
        }
    };
    assert_eq!(accept(100).await, Ok(true), "the first code");
    assert_eq!(accept(100).await, Ok(false), "the same step again");
    assert_eq!(accept(99).await, Ok(false), "an earlier step");
    assert_eq!(accept(101).await, Ok(true), "a later step");
    let opened = storage
        .factors
        .totp(&tenant("acme"), &kek, &user("user-1"))
        .await
        .expect("read")
        .expect("a factor");
    assert_eq!(opened.last_step, 101);
    assert!(
        matches!(
            storage
                .factors
                .accept_step(&tenant("acme"), &user("user-2"), 100)
                .await,
            Err(tessari_oauth_storage::Error::Invalid {
                record: "factor",
                ..
            })
        ),
        "no step without a factor"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn eight_requests_with_one_code_accept_it_once() {
    let storage = fresh(&tenant("acme"), 8).await;
    let kek = fresh_kek().expect("a key-encryption key");
    for round in 0..10_u64 {
        let id = format!("racer-{round}");
        enrolled(&storage, &kek, &id).await;
        let start = Arc::new(Barrier::new(8));
        let racers: Vec<_> = (0..8)
            .map(|_| {
                let storage = storage.clone();
                let start = Arc::clone(&start);
                let id = id.clone();
                tokio::spawn(async move {
                    start.wait().await;
                    storage
                        .factors
                        .accept_step(&tenant("acme"), &user(&id), 500)
                        .await
                })
            })
            .collect();
        let mut accepted = 0_u32;
        for racer in racers {
            match racer.await.expect("the task finished") {
                Ok(true) => accepted = accepted.saturating_add(1),
                Ok(false) => {}
                Err(failure) => assert_eq!(
                    failure.category(),
                    ErrorCategory::Conflict,
                    "only contention may refuse: {failure}"
                ),
            }
        }
        assert_eq!(
            accepted, 1,
            "round {round}: exactly one request accepts the step"
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn recovery_codes_are_replaced_as_a_set_and_spent_once_by_their_owner() {
    let storage = fresh(&tenant("acme"), 2).await;
    let spend = |id: &'static str, digest: String| {
        let storage = storage.clone();
        async move {
            storage
                .factors
                .spend_recovery_code(&tenant("acme"), &user(id), &digest)
                .await
        }
    };
    let (_, first) = code_set();
    storage
        .factors
        .issue_recovery_codes(&tenant("acme"), &user("user-1"), &first, NOW)
        .await
        .expect("issued");
    let (codes, second) = code_set();
    storage
        .factors
        .issue_recovery_codes(&tenant("acme"), &user("user-1"), &second, NOW)
        .await
        .expect("issued again");
    assert_eq!(
        spend("user-1", first[0].clone()).await,
        Ok(false),
        "a code of the replaced set no longer spends"
    );
    let typed = codes[0].to_lowercase().replace('-', " ");
    let digest = recovery_digest(&typed).expect("a digest");
    assert_eq!(spend("user-1", digest.clone()).await, Ok(true), "spent");
    assert_eq!(spend("user-1", digest).await, Ok(false), "spent once");
    assert_eq!(
        spend("user-2", second[1].clone()).await,
        Ok(false),
        "another user's code"
    );
    assert_eq!(
        spend("user-1", second[1].clone()).await,
        Ok(true),
        "still spends for its owner"
    );
    let (_, theirs) = code_set();
    storage
        .factors
        .issue_recovery_codes(&tenant("acme"), &user("user-2"), &theirs, NOW)
        .await
        .expect("issued");
    assert_eq!(
        spend("user-1", second[2].clone()).await,
        Ok(true),
        "another user's issue leaves this set alone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn sixteen_requests_with_one_recovery_code_spend_it_once() {
    let storage = fresh(&tenant("acme"), 16).await;
    for round in 0..5_u64 {
        let id = format!("spender-{round}");
        let (_, digests) = code_set();
        storage
            .factors
            .issue_recovery_codes(&tenant("acme"), &user(&id), &digests, NOW)
            .await
            .expect("issued");
        let start = Arc::new(Barrier::new(16));
        let racers: Vec<_> = (0..16)
            .map(|_| {
                let (storage, start, id) = (storage.clone(), Arc::clone(&start), id.clone());
                let digest = digests[0].clone();
                tokio::spawn(async move {
                    start.wait().await;
                    storage
                        .factors
                        .spend_recovery_code(&tenant("acme"), &user(&id), &digest)
                        .await
                })
            })
            .collect();
        let mut answers = Vec::new();
        for racer in racers {
            answers.push(racer.await.expect("the task finished"));
        }
        let spent = answers.iter().filter(|answer| **answer == Ok(true)).count();
        assert_eq!(spent, 1, "round {round}: {answers:?}");
        assert!(
            answers.iter().all(|answer| answer.is_ok()),
            "round {round}: a loser learns the code is gone, never a failure: {answers:?}"
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_pending_secret_is_kept_sealed_per_session_and_taken_once_by_its_own_user() {
    let storage = fresh(&tenant("acme"), 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    let factors = &storage.factors;
    factors
        .begin_totp(
            &tenant("acme"),
            &kek,
            &user("user-7"),
            "sid-a",
            b"first secret 0123456",
            NOW,
        )
        .await
        .expect("kept");
    factors
        .begin_totp(&tenant("acme"), &kek, &user("user-7"), "sid-a", SECRET, NOW)
        .await
        .expect("kept again");
    let theirs = factors
        .take_pending_totp(&tenant("acme"), &kek, &user("user-8"), "sid-a")
        .await
        .expect("the store answers");
    assert!(
        theirs.is_none(),
        "another user's session names nothing of theirs"
    );
    let taken = factors
        .take_pending_totp(&tenant("acme"), &kek, &user("user-7"), "sid-a")
        .await
        .expect("the store answers")
        .expect("pending");
    assert_eq!(taken.as_slice(), SECRET, "the latest secret, opened");
    let again = factors
        .take_pending_totp(&tenant("acme"), &kek, &user("user-7"), "sid-a")
        .await
        .expect("the store answers");
    assert!(again.is_none(), "taken once");
    assert!(
        factors
            .totp(&tenant("acme"), &kek, &user("user-7"))
            .await
            .expect("the store answers")
            .is_none(),
        "a pending secret is not an enrolled factor"
    );
}
