use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tessari_oauth_core::signin::{SigninKey, hold_secs};
use tessari_oauth_infrastructure::tessaridb::Place;
use tessari_oauth_types::Timestamp;

use super::hold_key;
use crate::throttle::ThrottleService;
use crate::throttle::repository::ThrottleRepository;
use crate::{Result, Tenancy};

const NOW: u64 = 1_000_000;

/// A backend whose counts are fixed and whose holds are kept as written.
struct Kept {
    failures: u64,
    holds: Mutex<HashMap<String, u64>>,
    /// Written by another failure between this one's read and its write, once, when given.
    interleaved: Mutex<Option<u64>>,
}

#[async_trait]
impl ThrottleRepository for Kept {
    async fn prepare(&self, _: &Place) -> Result<()> {
        Ok(())
    }

    async fn count(&self, _: &Place, _: &str, _: u64) -> Result<u64> {
        Ok(self.failures)
    }

    async fn hold(
        &self,
        _: &Place,
        key: &str,
        from: Option<u64>,
        until: u64,
        _: u64,
    ) -> Result<bool> {
        let mut holds = self.holds.lock().expect("unpoisoned");
        if let Some(other) = self.interleaved.lock().expect("unpoisoned").take() {
            holds.insert(key.to_owned(), other);
        }
        if holds.get(key).copied() != from {
            return Ok(false);
        }
        holds.insert(key.to_owned(), until);
        Ok(true)
    }

    async fn held_until(&self, _: &Place, key: &str) -> Result<Option<u64>> {
        Ok(self.holds.lock().expect("unpoisoned").get(key).copied())
    }

    async fn forget(&self, _: &Place, key: &str) -> Result<()> {
        self.holds.lock().expect("unpoisoned").remove(key);
        Ok(())
    }
}

#[tokio::test]
async fn a_failure_never_shortens_a_hold_another_failure_set() {
    // Two simultaneous failures counted 7 and 8: the one counted 8 wrote its hold first, the one counted 7 writes now.
    let longer = NOW + hold_secs(SigninKey::Account, 8);
    let key = hold_key(SigninKey::Account, "acme:digest-1");
    let kept = Arc::new(Kept {
        failures: 7,
        holds: Mutex::new(HashMap::from([(key.clone(), longer)])),
        interleaved: Mutex::new(None),
    });
    let service = ThrottleService::new(kept.clone(), Tenancy::for_region("eu").expect("a region"));
    service
        .signin_failed(
            &[(SigninKey::Account, "acme:digest-1")],
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("counted");
    assert_eq!(
        kept.holds.lock().expect("unpoisoned").get(&key).copied(),
        Some(longer),
        "the longer hold stands"
    );
}

#[tokio::test]
async fn a_write_that_lost_to_another_reads_the_hold_again() {
    let key = hold_key(SigninKey::Account, "acme:digest-2");
    let own = NOW + hold_secs(SigninKey::Account, 8);
    for (other, expected, case) in [
        (
            NOW + 1,
            own,
            "a shorter hold landed first: this one replaces it",
        ),
        (own + 50, own + 50, "a longer hold landed first: it stands"),
    ] {
        let kept = Arc::new(Kept {
            failures: 8,
            holds: Mutex::new(HashMap::new()),
            interleaved: Mutex::new(Some(other)),
        });
        let service =
            ThrottleService::new(kept.clone(), Tenancy::for_region("eu").expect("a region"));
        service
            .signin_failed(
                &[(SigninKey::Account, "acme:digest-2")],
                Timestamp::from_unix_secs(NOW),
            )
            .await
            .expect("counted");
        assert_eq!(
            kept.holds.lock().expect("unpoisoned").get(&key).copied(),
            Some(expected),
            "{case}"
        );
    }
}
