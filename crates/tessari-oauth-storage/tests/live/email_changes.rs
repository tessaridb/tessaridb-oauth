//! Address changes: confirmed once by the new address within a day, cancelled by the old one until applied, replaced
//! by a newer request, and applied only after the hold, in one transaction that never takes another account's
//! address.

use tessari_oauth_constants::{EMAIL_CHANGE_CONFIRM_SECS, EMAIL_CHANGE_HOLD_SECS};
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::email_changes::{Addresses, ConfirmedChange};
use tessari_oauth_storage::users::Registered;
use tessari_oauth_types::{EmailAddress, TenantId, Timestamp, UserId, VerifyToken};

use crate::fresh;

const NOW: u64 = 1_800_000_000;

fn at(seconds: u64) -> Timestamp {
    Timestamp::from_unix_secs(seconds)
}

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn email(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).expect("an address")
}

fn token(value: &str) -> VerifyToken {
    VerifyToken::from_secret(value)
}

async fn register(storage: &Storage, address: &str) -> UserId {
    let Registered::Created(user) = storage
        .users
        .register(&acme(), &email(address), at(NOW))
        .await
        .expect("registered")
    else {
        panic!("the address was free");
    };
    user
}

fn ada_to(new: &str) -> Addresses {
    Addresses {
        old: email("ada@example.com"),
        new: email(new),
    }
}

/// Ask for a change of `user` to `new`, confirmed by `confirm-<tag>` and cancelled by `cancel-<tag>`.
async fn ask(storage: &Storage, user: &UserId, new: &str, tag: &str, when: u64) {
    storage
        .email_changes
        .issue(
            &acme(),
            (
                &token(&format!("confirm-{tag}")),
                &token(&format!("cancel-{tag}")),
            ),
            user,
            &ada_to(new),
            at(when),
        )
        .await
        .expect("issued");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_change_is_confirmed_once_by_the_new_address_within_a_day() {
    let storage = fresh(&acme(), 2).await;
    let ada = register(&storage, "ada@example.com").await;
    ask(&storage, &ada, "ada@new.example", "1", NOW).await;

    let changes = &storage.email_changes;
    assert_eq!(
        changes
            .confirm(&acme(), &token("confirm-1"), at(NOW + 10))
            .await,
        Ok(Some(ConfirmedChange {
            user: ada.clone(),
            new_address: email("ada@new.example"),
            effective_at: at(NOW + EMAIL_CHANGE_HOLD_SECS),
        }))
    );
    assert_eq!(
        changes
            .confirm(&acme(), &token("confirm-1"), at(NOW + 20))
            .await,
        Ok(None),
        "used"
    );
    assert_eq!(
        changes
            .confirm(&acme(), &token("never"), at(NOW + 20))
            .await,
        Ok(None),
        "never issued"
    );
    assert_eq!(
        changes
            .confirm(&acme(), &token("cancel-1"), at(NOW + 20))
            .await,
        Ok(None),
        "the other link"
    );

    ask(&storage, &ada, "ada@later.example", "2", NOW).await;
    let late = NOW + EMAIL_CHANGE_CONFIRM_SECS + 1;
    assert_eq!(
        changes
            .confirm(&acme(), &token("confirm-2"), at(late))
            .await,
        Ok(None),
        "older than a day"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_old_address_cancels_a_change_and_a_newer_request_replaces_it() {
    let storage = fresh(&acme(), 2).await;
    let ada = register(&storage, "ada@example.com").await;
    let changes = &storage.email_changes;

    ask(&storage, &ada, "ada@new.example", "1", NOW).await;
    assert_eq!(
        changes.cancel(&acme(), &token("cancel-1")).await,
        Ok(Some((ada.clone(), ada_to("ada@new.example"))))
    );
    assert_eq!(
        changes.cancel(&acme(), &token("cancel-1")).await,
        Ok(None),
        "cancelled once"
    );
    assert_eq!(
        changes
            .confirm(&acme(), &token("confirm-1"), at(NOW + 1))
            .await,
        Ok(None),
        "gone"
    );

    ask(&storage, &ada, "ada@new.example", "2", NOW).await;
    ask(&storage, &ada, "ada@other.example", "3", NOW).await;
    assert_eq!(
        changes
            .confirm(&acme(), &token("confirm-2"), at(NOW + 1))
            .await,
        Ok(None),
        "replaced"
    );
    assert_eq!(
        changes.cancel(&acme(), &token("cancel-2")).await,
        Ok(None),
        "replaced"
    );
    assert!(
        changes
            .confirm(&acme(), &token("confirm-3"), at(NOW + 1))
            .await
            .expect("an answer")
            .is_some()
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_confirmed_change_is_applied_once_its_hold_is_over() {
    let storage = fresh(&acme(), 2).await;
    let ada = register(&storage, "ada@example.com").await;
    let changes = &storage.email_changes;
    ask(&storage, &ada, "ada@new.example", "1", NOW).await;
    let over = NOW + EMAIL_CHANGE_HOLD_SECS;

    assert_eq!(
        changes.due(&acme(), at(over), 10).await,
        Ok(Vec::new()),
        "not confirmed"
    );
    changes
        .confirm(&acme(), &token("confirm-1"), at(NOW + 10))
        .await
        .expect("confirmed");
    assert_eq!(
        changes.due(&acme(), at(over - 1), 10).await,
        Ok(Vec::new()),
        "held"
    );
    let due = changes.due(&acme(), at(over), 10).await.expect("due");
    assert_eq!(due.len(), 1, "{due:?}");
    assert_eq!(due[0].new_address, email("ada@new.example"));

    assert_eq!(changes.apply(&acme(), &due[0]).await, Ok(true));
    let moved = storage
        .users
        .find_by_email(&acme(), &email("ada@new.example"))
        .await
        .expect("an answer")
        .expect("the new address signs in");
    assert_eq!(moved.user, ada);
    assert!(moved.email_verified, "the link proved the new address");
    assert_eq!(
        storage
            .users
            .find_by_email(&acme(), &email("ada@example.com"))
            .await,
        Ok(None),
        "the old address is free"
    );
    assert_eq!(
        changes.due(&acme(), at(over), 10).await,
        Ok(Vec::new()),
        "applied once"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_change_to_an_address_another_account_holds_is_never_applied() {
    let storage = fresh(&acme(), 2).await;
    let ada = register(&storage, "ada@example.com").await;
    let bob = register(&storage, "bob@example.com").await;
    let changes = &storage.email_changes;
    ask(&storage, &ada, "bob@example.com", "1", NOW).await;
    changes
        .confirm(&acme(), &token("confirm-1"), at(NOW + 10))
        .await
        .expect("confirmed");
    let due = changes
        .due(&acme(), at(NOW + EMAIL_CHANGE_HOLD_SECS), 10)
        .await
        .expect("due");

    assert_eq!(due.len(), 1);
    assert_eq!(changes.apply(&acme(), &due[0]).await, Ok(false));
    let held = |address: &str| {
        let users = &storage.users;
        let address = email(address);
        async move {
            users
                .find_by_email(&acme(), &address)
                .await
                .expect("an answer")
        }
    };
    assert_eq!(
        held("bob@example.com").await.map(|account| account.user),
        Some(bob)
    );
    assert_eq!(
        held("ada@example.com").await.map(|account| account.user),
        Some(ada)
    );
}
