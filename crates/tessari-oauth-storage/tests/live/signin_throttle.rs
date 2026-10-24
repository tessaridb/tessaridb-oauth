//! Sign-in failures on a real node: a key is held only past its free failures, for a hold that doubles; the longest
//! hold of a sign-in's keys answers; a success clears the account and nothing else; simultaneous failures are each
//! counted; and a hold carries an expiry, so the store ends it.

use tessari_oauth_core::signin::{SigninKey, hold_secs};
use tessari_oauth_infrastructure::tessaridb::{Answer, Place, Value};
use tessari_oauth_storage::Storage;
use tessari_oauth_types::Timestamp;

use crate::throttle::prepared;

const NOW: u64 = 1_800_000_000;

fn at(secs: u64) -> Timestamp {
    Timestamp::from_unix_secs(secs)
}

async fn fail(storage: &Storage, key: SigninKey, value: &str, times: u64) {
    for _ in 0..times {
        storage
            .throttle
            .signin_failed(&[(key, value)], at(NOW))
            .await
            .expect("counted");
    }
}

async fn hold(storage: &Storage, keys: &[(SigninKey, &str)]) -> Option<u64> {
    storage
        .throttle
        .signin_hold(keys, at(NOW))
        .await
        .expect("answered")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_key_is_held_only_past_its_free_failures_and_the_hold_doubles() {
    let (storage, _, _) = prepared(2).await;
    let account = [(SigninKey::Account, "acme:digest-1")];
    assert_eq!(hold(&storage, &account).await, None, "no failures");
    fail(&storage, SigninKey::Account, "acme:digest-1", 5).await;
    assert_eq!(hold(&storage, &account).await, None, "free failures");
    fail(&storage, SigninKey::Account, "acme:digest-1", 1).await;
    assert_eq!(hold(&storage, &account).await, Some(1));
    fail(&storage, SigninKey::Account, "acme:digest-1", 1).await;
    assert_eq!(hold(&storage, &account).await, Some(2));
    assert_eq!(
        hold(&storage, &[(SigninKey::Account, "acme:digest-2")]).await,
        None,
        "another account"
    );
    assert_eq!(
        hold(&storage, &[(SigninKey::Pair, "acme:digest-1")]).await,
        None,
        "the same value under another kind is another key"
    );
    assert_eq!(
        storage
            .throttle
            .signin_hold(&account, at(NOW + 2))
            .await
            .expect("answered"),
        None,
        "a hold is over at its instant"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_longest_hold_answers_and_a_success_clears_only_the_account() {
    let (storage, _, _) = prepared(2).await;
    fail(&storage, SigninKey::Account, "acme:digest-1", 7).await;
    fail(&storage, SigninKey::Source, "203.0.113.9", 53).await;
    fail(&storage, SigninKey::Pair, "pair-1", 4).await;
    let keys = [
        (SigninKey::Account, "acme:digest-1"),
        (SigninKey::Source, "203.0.113.9"),
        (SigninKey::Pair, "pair-1"),
    ];
    assert_eq!(
        hold(&storage, &keys).await,
        Some(hold_secs(SigninKey::Source, 53)),
        "the source's four seconds"
    );
    storage
        .throttle
        .signin_succeeded("acme:digest-1")
        .await
        .expect("cleared");
    assert_eq!(
        hold(&storage, &[(SigninKey::Account, "acme:digest-1")]).await,
        None
    );
    fail(&storage, SigninKey::Account, "acme:digest-1", 5).await;
    assert_eq!(
        hold(&storage, &[(SigninKey::Account, "acme:digest-1")]).await,
        None,
        "the count started again"
    );
    assert_eq!(
        hold(&storage, &keys).await,
        Some(hold_secs(SigninKey::Source, 53)),
        "the source and the pair are untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_failures_are_each_counted() {
    let (storage, _, _) = prepared(8).await;
    let mut failures = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let storage = storage.clone();
        failures.spawn(async move {
            storage
                .throttle
                .signin_failed(&[(SigninKey::Account, "acme:digest-9")], at(NOW))
                .await
        });
    }
    while let Some(done) = failures.join_next().await {
        done.expect("the task finished").expect("counted");
    }
    assert_eq!(
        hold(&storage, &[(SigninKey::Account, "acme:digest-9")]).await,
        Some(hold_secs(SigninKey::Account, 8)),
        "eight failures, each counted"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_hold_carries_an_expiry_so_the_store_ends_it() {
    let (storage, database, namespace) = prepared(2).await;
    fail(&storage, SigninKey::Pair, "pair-7", 6).await;
    let answers = database
        .run_at(
            &Place::new(&namespace, "throttle").expect("a place"),
            "RETURN TTL counters:$key;",
            vec![("key".to_owned(), Value::from("hold:pair:pair-7"))],
        )
        .await
        .expect("answered");
    match answers.first() {
        Some(Answer::Value {
            value: Value::Duration { seconds, .. },
            ..
        }) => assert!(
            *seconds <= i64::try_from(hold_secs(SigninKey::Pair, 6)).expect("small"),
            "{seconds}"
        ),
        other => panic!("no expiry on the hold: {other:?}"),
    }
}
