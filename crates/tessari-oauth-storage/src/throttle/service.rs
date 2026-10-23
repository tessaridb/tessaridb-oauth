//! The throttle service: count a client's requests to a route group in fixed windows, and refuse past a limit.
//!
//! Each request adds one to the counter of its (group, window, client) and is admitted while the count stays within
//! the limit. A window is numbered from the epoch, so every server process counting into one store agrees on it. A
//! fixed window lets a client spend its limit at the end of one window and again at the start of the next: twice
//! the limit across a boundary, the price of one write per request. A store that does not answer is an error and
//! never an admission, so the caller refuses the request: the limit fails closed.
//!
//! Counters live in the region's own `throttle` database rather than in a tenant's, because the requests counted
//! include ones naming tenants that do not exist. Simultaneous requests write one counter, and a write the store answers
//! `retry` is made again, so each of them is counted.

use std::num::NonZeroU64;
use std::sync::Arc;

use tessari_oauth_constants::THROTTLE_WRITE_ATTEMPTS;
use tessari_oauth_types::Timestamp;

use super::model::Counters;
use super::repository::ThrottleRepository;
use crate::{Result, Tenancy, retry};

/// How many requests a client may make to a route group per window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// Requests admitted per window.
    pub requests: NonZeroU64,
    /// The window's length, in seconds.
    pub window_secs: NonZeroU64,
}

/// What counting a request decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Within the limit; the request may proceed.
    Admitted {
        /// Requests still admitted in this window.
        remaining: u64,
    },
    /// Past the limit; nothing is admitted until the window ends.
    Refused {
        /// Seconds until the window ends.
        retry_after_secs: u64,
    },
}

/// Request counters per route group and client.
#[derive(Clone)]
pub struct ThrottleService {
    pub(super) repository: Arc<dyn ThrottleRepository>,
    pub(super) tenancy: Tenancy,
}

/// The window `now` falls in under `limit`, and the seconds left in it (at least one).
fn window(limit: Limit, now: Timestamp) -> (u64, u64) {
    let length = limit.window_secs;
    let secs = now.unix_secs();
    let index = secs / length;
    let left = length.get().saturating_sub(secs % length);
    (index, left)
}

/// The counter's key. `group` is a name the caller's code chooses, never part of a request, and the window index
/// holds no `:`, so the client, which may, comes last and cannot make two counters share a key.
fn counter_key(group: &str, index: u64, client: &str) -> String {
    format!("{group}:{index}:{client}")
}

impl ThrottleService {
    pub(crate) fn new(repository: Arc<dyn ThrottleRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Make the region's counters exist; running it again changes nothing.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses a definition.
    pub async fn prepare(&self) -> Result<()> {
        self.repository.prepare(self.tenancy.throttle()).await
    }

    /// Count a request from `client` to `group` at `now`, and decide it under `limit`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or answers in a shape this crate cannot read.
    pub async fn admit(
        &self,
        group: &str,
        client: &str,
        limit: Limit,
        now: Timestamp,
    ) -> Result<Admission> {
        let (index, left) = window(limit, now);
        // The rest of the window plus one more: the store judges expiry on its own clock, and one running ahead of
        // this process's must not end a count while this process still counts into it.
        let seconds = left.saturating_add(limit.window_secs.get());
        let key = counter_key(group, index, client);
        let count = retry::bounded(THROTTLE_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository
                .count(self.tenancy.throttle(), Counters::Requests, &key, seconds)
        })
        .await?;
        Ok(if count > limit.requests.get() {
            Admission::Refused {
                retry_after_secs: left,
            }
        } else {
            Admission::Admitted {
                remaining: limit.requests.get().saturating_sub(count),
            }
        })
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
