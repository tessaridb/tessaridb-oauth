//! Password-reset tokens: a token found leaves it in place; spent once; a newer token replaces the older; a sign-in
//! cancels every token of the account; a token never issued resets nobody.

use tessari_oauth_types::{ResetToken, TenantId, Timestamp, UserId};

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn user(id: &str) -> UserId {
    UserId::parse(id).expect("a user id")
}

fn token(value: &str) -> ResetToken {
    ResetToken::from_secret(value)
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_token_is_found_in_place_and_spent_once() {
    let storage = fresh(&acme(), 2).await;
    storage
        .resets
        .issue(&acme(), &token("reset-1"), &user("user-1"), NOW)
        .await
        .expect("issued");

    assert_eq!(
        storage.resets.find(&acme(), &token("reset-1")).await,
        Ok(Some(user("user-1")))
    );
    assert_eq!(
        storage.resets.redeem(&acme(), &token("reset-1")).await,
        Ok(Some(user("user-1")))
    );
    assert_eq!(
        storage.resets.redeem(&acme(), &token("reset-1")).await,
        Ok(None)
    );
    assert_eq!(
        storage.resets.find(&acme(), &token("reset-1")).await,
        Ok(None)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_newer_token_replaces_the_older_for_that_account_only() {
    let storage = fresh(&acme(), 2).await;
    for (value, id) in [("old", "user-1"), ("other", "user-2"), ("new", "user-1")] {
        storage
            .resets
            .issue(&acme(), &token(value), &user(id), NOW)
            .await
            .expect("issued");
    }

    assert_eq!(
        storage.resets.redeem(&acme(), &token("old")).await,
        Ok(None)
    );
    assert_eq!(
        storage.resets.redeem(&acme(), &token("new")).await,
        Ok(Some(user("user-1")))
    );
    assert_eq!(
        storage.resets.redeem(&acme(), &token("other")).await,
        Ok(Some(user("user-2")))
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_sign_in_cancels_the_accounts_tokens() {
    let storage = fresh(&acme(), 2).await;
    storage
        .resets
        .issue(&acme(), &token("reset-1"), &user("user-1"), NOW)
        .await
        .expect("issued");
    storage
        .resets
        .issue(&acme(), &token("reset-2"), &user("user-2"), NOW)
        .await
        .expect("issued");

    assert_eq!(
        storage.resets.cancel(&acme(), &user("user-1")).await,
        Ok(())
    );

    assert_eq!(
        storage.resets.redeem(&acme(), &token("reset-1")).await,
        Ok(None)
    );
    assert_eq!(
        storage.resets.redeem(&acme(), &token("reset-2")).await,
        Ok(Some(user("user-2"))),
        "another account's token stands"
    );
}
