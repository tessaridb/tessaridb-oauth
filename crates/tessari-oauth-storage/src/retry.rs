//! Asking the store again: a bounded number of attempts, for the refusals that say asking again can work.
//!
//! The store reports contention rather than resolving it, and the retry is the caller's decision (only the caller
//! knows whether the work is still worth doing). Each domain names which refusals it retries and how many times;
//! this is only the loop. The two refusals worth retrying want different pauses: a lost compare-and-set means
//! another write already committed, so reading again after a short fixed pause finds it; a `retry` means a commit is
//! still landing, and the pause grows until it has.

use std::future::Future;
use std::time::Duration;

use tessari_oauth_constants::{STORE_RETRY_FIRST_PAUSE_MS, STORE_RETRY_MAX_PAUSE_MS};

use crate::{Error, Result};

/// What to do after a failed attempt.
pub(crate) enum Again {
    /// Stop and answer the failure.
    No,
    /// Try again after the short fixed pause: another writer won and its write is there to read.
    Soon,
    /// Try again after a pause that doubles each time: the store is still landing a commit.
    Later,
}

/// Run `attempt` until it succeeds, fails in a way `judge` answers [`Again::No`] to, or `attempts` have been made;
/// the last outcome is returned as it came.
pub(crate) async fn bounded<T, Attempt, Pending>(
    attempts: u32,
    judge: impl Fn(&Error) -> Again,
    mut attempt: Attempt,
) -> Result<T>
where
    Attempt: FnMut() -> Pending,
    Pending: Future<Output = Result<T>>,
{
    let short = Duration::from_millis(STORE_RETRY_FIRST_PAUSE_MS);
    let longest = Duration::from_millis(STORE_RETRY_MAX_PAUSE_MS);
    let mut growing = short;
    let mut made = 1;
    loop {
        let outcome = attempt().await;
        let again = match &outcome {
            Err(failure) => judge(failure),
            Ok(_) => Again::No,
        };
        let pause = match again {
            Again::No => return outcome,
            _ if made >= attempts => return outcome,
            Again::Soon => short,
            Again::Later => {
                let pause = growing;
                growing = growing.saturating_mul(2).min(longest);
                pause
            }
        };
        tokio::time::sleep(pause).await;
        made = made.saturating_add(1);
    }
}

/// Take a record by deleting it, once: `take` repeated on the store's `retry`, and when the attempts run out on a
/// refusal, `still_there` decides. Simultaneous deletes of one record keep meeting each other, so the attempts can
/// run out for every taker but the one that took it; a record that is gone was taken by another, and this taker
/// took nothing. A record still there keeps the refusal.
pub(crate) async fn take_once<T, Take, Taking, Look, Looking>(
    attempts: u32,
    take: Take,
    still_there: Look,
) -> Result<Option<T>>
where
    Take: FnMut() -> Taking,
    Taking: Future<Output = Result<Option<T>>>,
    Look: FnOnce() -> Looking,
    Looking: Future<Output = Result<bool>>,
{
    match bounded(attempts, on_store_retry, take).await {
        Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
            if still_there().await? {
                Err(refusal)
            } else {
                Ok(None)
            }
        }
        taken => taken,
    }
}

/// The judgement for a write that only the store's `retry` should repeat.
pub(crate) fn on_store_retry(failure: &Error) -> Again {
    match failure {
        Error::Store(store) if store.is_retry() => Again::Later,
        _ => Again::No,
    }
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod tests;
