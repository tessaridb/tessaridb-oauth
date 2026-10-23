//! The mail a company owes: queued sealed, claimed opened and held by the claim that took it, released to wait a
//! delay, finished once; a mail for no account is queued like any other; under another key nothing opens.

use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_storage::outbox::NewMail;
use tessari_oauth_test_support::{fresh_kek, unique};
use tessari_oauth_types::{EmailAddress, TenantId};

use crate::fresh;

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn mail(to: Option<&str>, subject: &str) -> NewMail {
    NewMail {
        to: to.map(|address| EmailAddress::parse(address).expect("an address")),
        subject: subject.to_owned(),
        text: format!("{subject}: open https://id.example.com/acme/reset#token-1"),
    }
}

/// A key-encryption key other than the one the mail was sealed under.
fn other_kek() -> Kek {
    let path = std::env::temp_dir().join(unique("kek-other"));
    std::fs::write(&path, [7_u8; 32]).expect("written");
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .expect("owner-only");
    let kek = Kek::load(&path).expect("another key");
    std::fs::remove_file(&path).expect("removed");
    kek
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_queued_mail_is_claimed_opened_held_and_finished_once() {
    let storage = fresh(&acme(), 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    storage
        .outbox
        .enqueue(&acme(), &kek, &mail(Some("ada@example.com"), "Reset"))
        .await
        .expect("queued");

    let taken = storage
        .outbox
        .claim(&acme(), &kek, 10)
        .await
        .expect("claimed");

    assert_eq!(taken.len(), 1, "{taken:?}");
    assert_eq!(
        taken[0].to.as_ref().map(EmailAddress::as_str),
        Some("ada@example.com")
    );
    assert_eq!(taken[0].subject, "Reset");
    assert_eq!(
        taken[0].text,
        "Reset: open https://id.example.com/acme/reset#token-1"
    );
    assert_eq!(taken[0].attempts, 1);
    assert!(
        storage
            .outbox
            .claim(&acme(), &kek, 10)
            .await
            .expect("claimed")
            .is_empty(),
        "held by the first claim"
    );
    assert_eq!(storage.outbox.finish(&acme(), &taken[0].id).await, Ok(true));
    assert_eq!(
        storage.outbox.finish(&acme(), &taken[0].id).await,
        Ok(false)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_mail_for_no_account_is_queued_like_any_other() {
    let storage = fresh(&acme(), 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    storage
        .outbox
        .enqueue(&acme(), &kek, &mail(None, "Reset"))
        .await
        .expect("queued");

    let taken = storage
        .outbox
        .claim(&acme(), &kek, 10)
        .await
        .expect("claimed");

    assert_eq!(taken.len(), 1, "{taken:?}");
    assert_eq!(taken[0].to, None);
    assert_eq!(taken[0].subject, "Reset");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_retried_mail_waits_its_delay() {
    let storage = fresh(&acme(), 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    for subject in ["first", "second"] {
        storage
            .outbox
            .enqueue(&acme(), &kek, &mail(Some("ada@example.com"), subject))
            .await
            .expect("queued");
    }
    let mut taken = storage
        .outbox
        .claim(&acme(), &kek, 10)
        .await
        .expect("claimed");
    taken.sort_by(|left, right| left.subject.cmp(&right.subject));
    let (now, later) = (&taken[0], &taken[1]);
    assert_eq!(storage.outbox.retry(&acme(), &now.id, 0).await, Ok(()));
    assert_eq!(storage.outbox.retry(&acme(), &later.id, 60).await, Ok(()));

    let again = storage
        .outbox
        .claim(&acme(), &kek, 10)
        .await
        .expect("claimed");

    assert_eq!(again.len(), 1, "the delayed one is not due: {again:?}");
    assert_eq!(again[0].id, now.id);
    assert_eq!(again[0].subject, "first");
    assert_eq!(again[0].attempts, 2);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_mail_sealed_under_another_key_does_not_open() {
    let storage = fresh(&acme(), 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    storage
        .outbox
        .enqueue(&acme(), &kek, &mail(Some("ada@example.com"), "Reset"))
        .await
        .expect("queued");

    let refused = storage.outbox.claim(&acme(), &other_kek(), 10).await;

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
