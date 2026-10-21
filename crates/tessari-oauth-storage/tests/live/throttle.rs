//! Request counters on a real node: each (group, window, client) counted apart, refused past its limit, and a
//! counter that expires on its own.

use std::num::NonZeroU64;

use tessari_oauth_infrastructure::tessaridb::{Answer, Database, Place, Value};
use tessari_oauth_storage::throttle::{Admission, Limit};
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_test_support::{plain_node, unique};
use tessari_oauth_types::Timestamp;

const NOW: u64 = 1_800_000_010;

fn limit(requests: u64, window_secs: u64) -> Limit {
    Limit {
        requests: NonZeroU64::new(requests).expect("non-zero"),
        window_secs: NonZeroU64::new(window_secs).expect("non-zero"),
    }
}

/// Storage over a pool of `connections` for a fresh region with its counters prepared, the database handle, and the
/// region's namespace.
async fn prepared(connections: usize) -> (Storage, Database, String) {
    let database =
        Database::new(plain_node().expect("the plain node is named"), connections).expect("a pool");
    let region = unique("live");
    let tenancy = Tenancy::for_region(&region).expect("a region");
    let storage = Storage::new(&database, &tenancy);
    storage.throttle.prepare().await.expect("prepared");
    (storage, database, format!("oauth_{region}"))
}

async fn admit(storage: &Storage, group: &str, client: &str) -> Admission {
    storage
        .throttle
        .admit(group, client, limit(2, 60), Timestamp::from_unix_secs(NOW))
        .await
        .expect("answered")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_is_refused_past_its_limit_while_other_clients_and_groups_are_counted_apart() {
    let (storage, _, _) = prepared(2).await;
    storage.throttle.prepare().await.expect("prepared again");
    assert_eq!(
        admit(&storage, "metadata", "203.0.113.9").await,
        Admission::Admitted
    );
    assert_eq!(
        admit(&storage, "metadata", "203.0.113.9").await,
        Admission::Admitted
    );
    assert_eq!(
        admit(&storage, "metadata", "203.0.113.9").await,
        Admission::Refused {
            retry_after_secs: 50
        }
    );
    assert_eq!(
        admit(&storage, "metadata", "198.51.100.7").await,
        Admission::Admitted
    );
    assert_eq!(
        admit(&storage, "jwks", "203.0.113.9").await,
        Admission::Admitted
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_counter_expires_by_itself_after_its_window_and_one_more() {
    let (storage, database, namespace) = prepared(2).await;
    admit(&storage, "metadata", "203.0.113.9").await;
    admit(&storage, "metadata", "203.0.113.9").await;
    let place = Place::new(namespace, "throttle").expect("a place");
    let key = format!("metadata:{}:203.0.113.9", NOW / 60);
    let answers = database
        .run_at(
            &place,
            "RETURN TTL counters:$key;",
            vec![("key".to_owned(), Value::from(key.as_str()))],
        )
        .await
        .expect("answered");
    // 50 seconds were left in the window, plus one more window: the second `INCR` kept the first write's expiry.
    match answers.first() {
        Some(Answer::Value {
            value: Value::Duration { seconds, .. },
            ..
        }) => assert!((100..=110).contains(seconds), "{seconds}"),
        other => panic!("no expiry on the counter: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_requests_are_each_counted_once_so_exactly_the_limit_is_admitted() {
    // One connection per request, so the sixteen counts reach the node at once rather than two at a time.
    let (storage, _, _) = prepared(16).await;
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let storage = storage.clone();
        requests.spawn(async move {
            storage
                .throttle
                .admit(
                    "metadata",
                    "203.0.113.9",
                    limit(10, 60),
                    Timestamp::from_unix_secs(NOW),
                )
                .await
                .expect("answered")
        });
    }
    let mut admitted = 0;
    let mut refused = 0;
    while let Some(answer) = requests.join_next().await {
        match answer.expect("a request task") {
            Admission::Admitted => admitted += 1,
            Admission::Refused { .. } => refused += 1,
        }
    }
    assert_eq!((admitted, refused), (10, 6));
}
