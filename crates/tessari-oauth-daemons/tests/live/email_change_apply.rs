//! Address changes applied: nothing moves before the hold is over; then a free new address becomes the account's,
//! verified, the old one is let go and both are told, while a change to an address another account holds is dropped
//! and only the old address is told; a second run finds nothing left.

use std::sync::Arc;
use std::time::Duration;

use tessari_oauth_constants::EMAIL_CHANGE_HOLD_SECS;
use tessari_oauth_daemons::{Daemon, EmailChangeApply};
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::audit::AuditKind;
use tessari_oauth_storage::companies::Served;
use tessari_oauth_storage::email_changes::Addresses;
use tessari_oauth_storage::users::Registered;
use tessari_oauth_types::{EmailAddress, TenantId, Timestamp, UserId, VerifyToken};

use crate::{fresh_kek, storage};

const NOW: u64 = 1_800_000_000;

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn email(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).expect("an address")
}

fn daemon(storage: &Storage, kek: &Arc<Kek>, at: u64) -> EmailChangeApply {
    let served = Served::new("https://id.example.com");
    served.replace([acme()]);
    EmailChangeApply {
        email_changes: Arc::clone(&storage.email_changes),
        outbox: Arc::clone(&storage.outbox),
        audit: Arc::clone(&storage.audit),
        kek: Arc::clone(kek),
        served: Arc::new(served),
        clock: Arc::new(move || Timestamp::from_unix_secs(at)),
        interval: Duration::from_secs(60),
        timeout: Duration::from_secs(45),
    }
}

async fn register(storage: &Storage, address: &str) -> UserId {
    let Registered::Created(user) = storage
        .users
        .register(&acme(), &email(address), Timestamp::from_unix_secs(NOW))
        .await
        .expect("registered")
    else {
        panic!("the address was free");
    };
    user
}

/// Ask for `user`'s change from `old` to `new` at NOW and confirm it ten seconds later.
async fn confirmed(storage: &Storage, user: &UserId, (old, new): (&str, &str)) {
    let confirm = VerifyToken::from_secret(format!("confirm-{old}"));
    let cancel = VerifyToken::from_secret(format!("cancel-{old}"));
    let addresses = Addresses {
        old: email(old),
        new: email(new),
    };
    let changes = &storage.email_changes;
    changes
        .issue(
            &acme(),
            (&confirm, &cancel),
            user,
            &addresses,
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("issued");
    let confirmed = changes
        .confirm(&acme(), &confirm, Timestamp::from_unix_secs(NOW + 10))
        .await
        .expect("the store answers");
    assert!(confirmed.is_some(), "confirmed within the day");
}

async fn holder(storage: &Storage, address: &str) -> Option<UserId> {
    storage
        .users
        .find_by_email(&acme(), &email(address))
        .await
        .expect("the store answers")
        .map(|account| account.user)
}

/// The recipients of the queued mail, sorted, after checking that none carries a link.
async fn notified(storage: &Storage, kek: &Kek) -> Vec<String> {
    let mails = storage
        .outbox
        .claim(&acme(), kek, 50)
        .await
        .expect("claimed");
    let mut to: Vec<String> = mails
        .iter()
        .map(|mail| {
            assert!(!mail.text.contains("/login/"), "a notice carries no link");
            mail.to.as_ref().expect("addressed").as_str().to_owned()
        })
        .collect();
    to.sort();
    to
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_due_change_moves_the_account_and_a_taken_address_is_refused() {
    let storage = storage();
    storage
        .tenants
        .provision(&acme())
        .await
        .expect("provisioned");
    let kek = fresh_kek();
    let ada = register(&storage, "ada@example.com").await;
    let carol = register(&storage, "carol@example.com").await;
    let bob = register(&storage, "bob@example.com").await;
    confirmed(&storage, &ada, ("ada@example.com", "ada@new.example")).await;
    confirmed(&storage, &carol, ("carol@example.com", "bob@example.com")).await;

    let early = daemon(&storage, &kek, NOW + EMAIL_CHANGE_HOLD_SECS - 1);
    early.run_once().await.expect("a run");
    assert_eq!(holder(&storage, "ada@example.com").await, Some(ada.clone()));
    assert!(notified(&storage, &kek).await.is_empty(), "still held");

    let due = daemon(&storage, &kek, NOW + EMAIL_CHANGE_HOLD_SECS);
    let report = due.run_once().await.expect("a run");
    assert_eq!(report.message, "tenants=1 applied=1 refused=1");
    let moved = storage
        .users
        .find_by_email(&acme(), &email("ada@new.example"))
        .await
        .expect("the store answers")
        .expect("the new address signs in");
    assert_eq!(moved.user, ada);
    assert!(moved.email_verified, "the link proved the new address");
    assert_eq!(holder(&storage, "ada@example.com").await, None);
    assert_eq!(
        holder(&storage, "carol@example.com").await,
        Some(carol.clone())
    );
    assert_eq!(holder(&storage, "bob@example.com").await, Some(bob));
    assert_eq!(
        notified(&storage, &kek).await,
        ["ada@example.com", "ada@new.example", "carol@example.com"]
    );
    let trail = storage
        .audit
        .read_after(&acme(), 0, 100)
        .await
        .expect("the trail reads");
    let outcome = |user: &UserId| {
        trail
            .iter()
            .filter(|record| {
                record.event.kind == AuditKind::AddressChanged
                    && record.event.user.as_ref() == Some(user)
            })
            .filter_map(|record| record.event.reason.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(outcome(&ada), ["applied"]);
    assert_eq!(outcome(&carol), ["refused"]);
    assert!(
        !format!("{trail:?}").contains("@"),
        "no address is recorded"
    );

    let again = due.run_once().await.expect("a run");
    assert_eq!(again.message, "tenants=1 applied=0 refused=0");
    assert!(notified(&storage, &kek).await.is_empty());
}
