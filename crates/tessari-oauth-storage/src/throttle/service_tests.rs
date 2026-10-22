use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;
use tessari_oauth_types::Timestamp;

use super::{Admission, Limit, ThrottleService, counter_key, window};
use crate::throttle::repository::ThrottleRepository;
use crate::{Error, Result, Tenancy};

fn limit(requests: u64, window_secs: u64) -> Limit {
    Limit {
        requests: NonZeroU64::new(requests).expect("non-zero"),
        window_secs: NonZeroU64::new(window_secs).expect("non-zero"),
    }
}

#[test]
fn a_window_is_numbered_from_the_epoch_and_reports_the_seconds_left_in_it() {
    let minute = limit(1, 60);
    assert_eq!(window(minute, Timestamp::from_unix_secs(1_000)), (16, 20));
    assert_eq!(window(minute, Timestamp::from_unix_secs(960)), (16, 60));
    assert_eq!(window(minute, Timestamp::from_unix_secs(1_019)), (16, 1));
    assert_eq!(window(minute, Timestamp::from_unix_secs(1_020)), (17, 60));
}

#[test]
fn a_counter_is_keyed_by_its_group_its_window_and_its_client() {
    assert_eq!(
        counter_key("metadata", 16, "203.0.113.9"),
        "metadata:16:203.0.113.9"
    );
    assert_ne!(
        counter_key("metadata", 16, "2001:db8::"),
        counter_key("metadata", 17, "2001:db8::")
    );
}

/// A backend answering the counts it is given, in order, and recording what it was asked.
struct Counts {
    answers: Mutex<Vec<u64>>,
    asked: Mutex<Vec<(Place, String, u64)>>,
}

#[async_trait]
impl ThrottleRepository for Counts {
    async fn prepare(&self, _: &Place) -> Result<()> {
        Ok(())
    }

    async fn count(&self, place: &Place, key: &str, seconds: u64) -> Result<u64> {
        self.asked
            .lock()
            .expect("unpoisoned")
            .push((place.clone(), key.to_owned(), seconds));
        Ok(self.answers.lock().expect("unpoisoned").remove(0))
    }

    async fn hold(&self, _: &Place, _: &str, _: Option<u64>, _: u64, _: u64) -> Result<bool> {
        Ok(true)
    }

    async fn held_until(&self, _: &Place, _: &str) -> Result<Option<u64>> {
        Ok(None)
    }

    async fn forget(&self, _: &Place, _: &str) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn a_client_is_admitted_up_to_the_limit_and_refused_until_its_window_ends() {
    let counts = Arc::new(Counts {
        answers: Mutex::new(vec![1, 2, 3, 4]),
        asked: Mutex::new(Vec::new()),
    });
    let tenancy = Tenancy::for_region("eu").expect("a region");
    let service = ThrottleService::new(counts.clone(), tenancy);
    let at = Timestamp::from_unix_secs(1_000);
    let mut seen = Vec::new();
    for _ in 0..4 {
        seen.push(
            service
                .admit("metadata", "203.0.113.9", limit(3, 60), at)
                .await
                .expect("answered"),
        );
    }
    assert_eq!(
        seen,
        [
            Admission::Admitted { remaining: 2 },
            Admission::Admitted { remaining: 1 },
            Admission::Admitted { remaining: 0 },
            Admission::Refused {
                retry_after_secs: 20
            }
        ]
    );
    let asked = counts.asked.lock().expect("unpoisoned");
    let (place, key, seconds) = &asked[0];
    assert_eq!(
        (place.namespace(), place.database()),
        ("oauth_eu", "throttle")
    );
    assert_eq!(key, "metadata:16:203.0.113.9");
    // The rest of the window plus one more, so a store clock running ahead cannot end the count early.
    assert_eq!(*seconds, 80);
}

/// A backend that never answers.
struct Down;

#[async_trait]
impl ThrottleRepository for Down {
    async fn prepare(&self, _: &Place) -> Result<()> {
        Err(down())
    }

    async fn count(&self, _: &Place, _: &str, _: u64) -> Result<u64> {
        Err(down())
    }

    async fn hold(&self, _: &Place, _: &str, _: Option<u64>, _: u64, _: u64) -> Result<bool> {
        Err(down())
    }

    async fn held_until(&self, _: &Place, _: &str) -> Result<Option<u64>> {
        Err(down())
    }

    async fn forget(&self, _: &Place, _: &str) -> Result<()> {
        Err(down())
    }
}

fn down() -> Error {
    Error::Store(tessari_oauth_infrastructure::Error::Unavailable {
        message: "the node is down".to_owned(),
    })
}

#[tokio::test]
async fn a_store_that_does_not_answer_is_an_error_never_an_admission() {
    let service =
        ThrottleService::new(Arc::new(Down), Tenancy::for_region("eu").expect("a region"));
    let admitted = service
        .admit(
            "metadata",
            "203.0.113.9",
            limit(3, 60),
            Timestamp::from_unix_secs(0),
        )
        .await;
    assert!(matches!(admitted, Err(Error::Store(_))), "{admitted:?}");
}
