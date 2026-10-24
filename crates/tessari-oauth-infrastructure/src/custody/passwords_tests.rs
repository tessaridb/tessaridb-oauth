use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use tessari_oauth_constants::{
    PASSWORD_HASH_ITERATIONS_FLOOR, PASSWORD_HASH_MEMORY_KIB_FLOOR, PASSWORD_HASH_PARALLELISM_FLOOR,
};

use super::{DUMMY_PASSWORD, PasswordCost, Passwords, Verdict};
use crate::Error;

static FILES: AtomicU32 = AtomicU32::new(0);

const PASSWORD: &str = "correct horse battery staple";

/// A pepper file of `bytes` with `mode`, in a path nobody else uses.
fn file(bytes: &[u8], mode: u32) -> PathBuf {
    let turn = FILES.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("pepper-test-{}-{turn}", std::process::id()));
    std::fs::write(&path, bytes).expect("written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode set");
    path
}

fn floor() -> PasswordCost {
    PasswordCost::new(
        PASSWORD_HASH_MEMORY_KIB_FLOOR,
        PASSWORD_HASH_ITERATIONS_FLOOR,
        PASSWORD_HASH_PARALLELISM_FLOOR,
    )
    .expect("the floor is a cost")
}

fn passwords_at(pepper: u8, cost: PasswordCost, concurrency: usize) -> Arc<Passwords> {
    Passwords::load(&file(&[pepper; 32], 0o600), cost, concurrency).expect("loaded")
}

fn passwords(pepper: u8) -> Arc<Passwords> {
    passwords_at(pepper, floor(), 4)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_verifies_against_its_own_hash_and_no_other_does() {
    let passwords = passwords(1);
    let stored = passwords.hash(PASSWORD).await.expect("hashed");
    assert!(
        stored.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"),
        "{stored}"
    );
    assert!(!stored.contains(PASSWORD));
    assert_ne!(
        stored,
        passwords.hash(PASSWORD).await.expect("hashed"),
        "a fresh salt each time"
    );
    assert_eq!(
        passwords.verify(PASSWORD, Some(&stored)).await,
        Ok(Verdict::Match { rehash: false })
    );
    for other in [
        "correct horse battery stapl",
        "Correct horse battery staple",
        "",
    ] {
        assert_eq!(
            passwords.verify(other, Some(&stored)).await,
            Ok(Verdict::Mismatch),
            "{other:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_hash_is_keyed_by_the_pepper() {
    let stored = passwords(1).hash(PASSWORD).await.expect("hashed");
    assert_eq!(
        passwords(2).verify(PASSWORD, Some(&stored)).await,
        Ok(Verdict::Mismatch),
        "another pepper"
    );
    let parsed = PasswordHash::new(&stored).expect("a PHC string");
    let plain = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::try_from(&parsed).expect("its parameters"),
    );
    assert!(
        plain.verify_password(PASSWORD.as_bytes(), &parsed).is_err(),
        "the stored hash is not Argon2id of the bare password"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_characters_in_another_normal_form_are_the_same_password() {
    let passwords = passwords(1);
    let composed = "caf\u{e9} au lait, bien s\u{fb}r";
    let decomposed = "cafe\u{301} au lait, bien su\u{302}r";
    let stored = passwords.hash(composed).await.expect("hashed");
    assert_eq!(
        passwords.verify(decomposed, Some(&stored)).await,
        Ok(Verdict::Match { rehash: false })
    );
}

/// The quickest of three runs of `check`.
async fn quickest<F, Fut>(check: F) -> Duration
where
    F: Fn() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let started = Instant::now();
        check().await;
        best = best.min(started.elapsed());
    }
    best
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_account_costs_a_full_hash_and_never_matches() {
    let passwords = passwords(1);
    let stored = passwords.hash(PASSWORD).await.expect("hashed");
    assert_eq!(
        passwords.verify(PASSWORD, None).await,
        Ok(Verdict::Mismatch)
    );
    assert_eq!(
        passwords.verify(DUMMY_PASSWORD, None).await,
        Ok(Verdict::Mismatch),
        "not even the dummy's own password"
    );
    let known = quickest(|| async {
        let _ = passwords.verify("a wrong guess", Some(&stored)).await;
    })
    .await;
    let unknown = quickest(|| async {
        let _ = passwords.verify("a wrong guess", None).await;
    })
    .await;
    assert!(
        unknown.saturating_mul(2) >= known,
        "unknown {unknown:?} against known {known:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hash_made_below_the_current_cost_asks_to_be_made_again() {
    let stored = passwords(1).hash(PASSWORD).await.expect("hashed");
    let raised = PasswordCost::new(PASSWORD_HASH_MEMORY_KIB_FLOOR, 4, 1).expect("a cost");
    let passwords = passwords_at(1, raised, 4);
    assert_eq!(
        passwords.verify(PASSWORD, Some(&stored)).await,
        Ok(Verdict::Match { rehash: true })
    );
    assert_eq!(
        passwords.verify("a wrong guess", Some(&stored)).await,
        Ok(Verdict::Mismatch),
        "no rehash on a mismatch"
    );
    let fresh = passwords.hash(PASSWORD).await.expect("hashed");
    assert_eq!(
        passwords.verify(PASSWORD, Some(&fresh)).await,
        Ok(Verdict::Match { rehash: false })
    );
}

#[test]
fn a_cost_below_the_floor_is_refused() {
    for (memory, iterations, parallelism) in [
        (PASSWORD_HASH_MEMORY_KIB_FLOOR - 1, 3, 1),
        (PASSWORD_HASH_MEMORY_KIB_FLOOR, 2, 1),
        (PASSWORD_HASH_MEMORY_KIB_FLOOR, 3, 0),
    ] {
        assert!(
            matches!(
                PasswordCost::new(memory, iterations, parallelism),
                Err(Error::InvalidConfig {
                    field: "password_hash_cost",
                    ..
                })
            ),
            "{memory} {iterations} {parallelism}"
        );
    }
}

#[test]
fn a_pepper_file_others_can_read_or_too_short_is_refused() {
    for path in [
        file(&[1; 32], 0o640),
        file(&[1; 32], 0o604),
        file(&[1; 31], 0o600),
        std::env::temp_dir().join("pepper-test-absent"),
    ] {
        assert!(
            matches!(
                Passwords::load(&path, floor(), 1),
                Err(Error::InvalidConfig {
                    field: "password_pepper",
                    ..
                })
            ),
            "{}",
            path.display()
        );
    }
    assert!(Passwords::load(&file(&[1; 64], 0o400), floor(), 1).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stored_value_that_is_not_an_argon2id_hash_is_refused() {
    let passwords = passwords(1);
    for stored in [
        "not a hash",
        "$argon2i$v=19$m=65536,t=3,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
        "$2b$12$abcdefghijklmnopqrstuuJ0rD6d0b6Kq3QeJ1n9eQ8u1H5ZqXQyG",
    ] {
        assert!(
            matches!(
                passwords.verify(PASSWORD, Some(stored)).await,
                Err(Error::Custody { .. })
            ),
            "{stored}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hashes_beyond_the_concurrency_bound_wait_their_turn() {
    let single = passwords_at(1, floor(), 1);
    let alone = quickest(|| async {
        let _ = single.hash(PASSWORD).await;
    })
    .await;
    let started = Instant::now();
    let (first, second, third) = tokio::join!(
        single.hash(PASSWORD),
        single.hash(PASSWORD),
        single.hash(PASSWORD)
    );
    let together = started.elapsed();
    assert!(first.is_ok() && second.is_ok() && third.is_ok());
    assert!(
        together.saturating_mul(2) >= alone.saturating_mul(5),
        "three at one-at-a-time took {together:?}; one alone {alone:?}"
    );
}

#[test]
fn the_sign_in_keys_come_from_the_pepper() {
    let email = "ada@example.com";
    assert_eq!(
        passwords(1).signin_keys().account("acme", email),
        passwords(1).signin_keys().account("acme", email),
        "one pepper, one key"
    );
    assert_ne!(
        passwords(1).signin_keys().account("acme", email),
        passwords(2).signin_keys().account("acme", email),
        "another pepper"
    );
}
