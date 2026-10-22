//! Records taken by deleting them answer one taker and tell every simultaneous one that there was nothing to take:
//! a sign-in finished by sixteen requests at once is finished once, and a session ended by sixteen is ended once,
//! with no taker failing.

use std::future::Future;
use std::sync::Arc;

use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::Storage;
use tessari_oauth_types::{SessionSecret, SigninBinding, TenantId, Timestamp, UserId};
use tokio::sync::Barrier;

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);
const TAKERS: usize = 16;
const ROUNDS: u64 = 5;

fn tenant() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

/// Run `take` from `TAKERS` tasks released together; answer what each got.
async fn race<T, F, Fut>(storage: &Storage, take: F) -> Vec<tessari_oauth_storage::Result<T>>
where
    T: Send + 'static,
    F: Fn(Storage) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = tessari_oauth_storage::Result<T>> + Send + 'static,
{
    let start = Arc::new(Barrier::new(TAKERS));
    let racers: Vec<_> = (0..TAKERS)
        .map(|_| {
            let (storage, start, take) = (storage.clone(), Arc::clone(&start), take.clone());
            tokio::spawn(async move {
                start.wait().await;
                take(storage).await
            })
        })
        .collect();
    let mut answers = Vec::new();
    for racer in racers {
        answers.push(racer.await.expect("the task finished"));
    }
    answers
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn sixteen_simultaneous_finishes_of_one_sign_in_finish_it_once() {
    let storage = fresh(&tenant(), TAKERS).await;
    for round in 0..ROUNDS {
        let browser = format!("browser-{round}");
        let begun = storage
            .signins
            .begin(
                &tenant(),
                &SigninBinding::from_secret(&browser),
                "interaction-1",
                NOW,
            )
            .await;
        assert_eq!(begun, Ok(true));
        let answers = race(&storage, move |storage| {
            let browser = browser.clone();
            async move {
                storage
                    .signins
                    .finish(&tenant(), &SigninBinding::from_secret(&browser), NOW)
                    .await
            }
        })
        .await;
        let finished = answers
            .iter()
            .filter(|answer| matches!(answer, Ok(Some(_))))
            .count();
        assert_eq!(finished, 1, "round {round}: {answers:?}");
        assert!(
            answers.iter().all(Result::is_ok),
            "round {round}: {answers:?}"
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn sixteen_simultaneous_ends_of_one_session_end_it_once() {
    let storage = fresh(&tenant(), TAKERS).await;
    let user = UserId::parse("user-1").expect("a user id");
    for round in 0..ROUNDS {
        let cookie = format!("cookie-{round}");
        let opened = storage
            .sessions
            .create(
                &tenant(),
                &SessionSecret::from_secret(&cookie),
                &user,
                &[Method::Password],
                NOW,
            )
            .await;
        assert_eq!(opened, Ok(()));
        let answers = race(&storage, move |storage| {
            let cookie = cookie.clone();
            async move {
                storage
                    .sessions
                    .end(&tenant(), &SessionSecret::from_secret(&cookie))
                    .await
            }
        })
        .await;
        let ended = answers.iter().filter(|answer| **answer == Ok(true)).count();
        assert_eq!(ended, 1, "round {round}: {answers:?}");
        assert!(
            answers.iter().all(Result::is_ok),
            "round {round}: {answers:?}"
        );
    }
}
