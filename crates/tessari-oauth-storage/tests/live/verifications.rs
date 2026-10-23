//! Address-verification tokens: spent once, naming the account and the address they were sent to; a newer token
//! replaces the older for that account only; marking an address verified holds only while the address is still the
//! account's.

use tessari_oauth_storage::users::Registered;
use tessari_oauth_types::{EmailAddress, TenantId, Timestamp, UserId, VerifyToken};

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn user(id: &str) -> UserId {
    UserId::parse(id).expect("a user id")
}

fn email(raw: &str) -> EmailAddress {
    EmailAddress::parse(raw).expect("an address")
}

fn token(value: &str) -> VerifyToken {
    VerifyToken::from_secret(value)
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_token_is_spent_once_and_names_its_account_and_address() {
    let storage = fresh(&acme(), 2).await;
    storage
        .verifications
        .issue(
            &acme(),
            &token("verify-1"),
            &user("user-1"),
            &email("ada@example.com"),
            NOW,
        )
        .await
        .expect("issued");

    assert_eq!(
        storage
            .verifications
            .redeem(&acme(), &token("verify-1"))
            .await,
        Ok(Some((user("user-1"), email("ada@example.com"))))
    );
    assert_eq!(
        storage
            .verifications
            .redeem(&acme(), &token("verify-1"))
            .await,
        Ok(None)
    );
    assert_eq!(
        storage.verifications.redeem(&acme(), &token("never")).await,
        Ok(None)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_newer_token_replaces_the_older_for_that_account_only() {
    let storage = fresh(&acme(), 2).await;
    for (value, id) in [("old", "user-1"), ("other", "user-2"), ("new", "user-1")] {
        storage
            .verifications
            .issue(
                &acme(),
                &token(value),
                &user(id),
                &email("x@example.com"),
                NOW,
            )
            .await
            .expect("issued");
    }

    assert_eq!(
        storage.verifications.redeem(&acme(), &token("old")).await,
        Ok(None)
    );
    assert_eq!(
        storage.verifications.redeem(&acme(), &token("new")).await,
        Ok(Some((user("user-1"), email("x@example.com"))))
    );
    assert_eq!(
        storage.verifications.redeem(&acme(), &token("other")).await,
        Ok(Some((user("user-2"), email("x@example.com"))))
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_address_is_marked_verified_only_for_the_account_that_holds_it() {
    let storage = fresh(&acme(), 2).await;
    let Registered::Created(ada) = storage
        .users
        .register(&acme(), &email("ada@example.com"), NOW)
        .await
        .expect("registered")
    else {
        panic!("the address was free");
    };

    assert_eq!(
        storage
            .users
            .mark_verified(
                &acme(),
                &user("someone-else"),
                &email("ada@example.com"),
                NOW
            )
            .await,
        Ok(false),
        "another account's claim marks nothing"
    );
    assert_eq!(
        storage
            .users
            .mark_verified(&acme(), &ada, &email("nobody@example.com"), NOW)
            .await,
        Ok(false),
        "an address the account does not hold marks nothing"
    );
    let before = storage
        .users
        .find(&acme(), &ada)
        .await
        .expect("an answer")
        .expect("the account");
    assert!(!before.email_verified);

    assert_eq!(
        storage
            .users
            .mark_verified(&acme(), &ada, &email("ada@example.com"), NOW)
            .await,
        Ok(true)
    );
    let after = storage
        .users
        .find(&acme(), &ada)
        .await
        .expect("an answer")
        .expect("the account");
    assert!(after.email_verified);
}
