//! The assertion service: spend a client assertion once.
//!
//! Single use is a concurrency property, so the spend is one conditional write that answers who won; nothing is
//! read first. A `retry` from the store is answered by asking again a bounded number of times. Should the first
//! attempt have landed after all, the retry is told the key exists and the assertion is refused as a replay — the
//! client signs a new one, and nothing is ever accepted twice.

use std::sync::Arc;

use tessari_oauth_constants::{ASSERTION_SPEND_ATTEMPTS, CLOCK_SKEW_SECS};
use tessari_oauth_core::assertion::AssertionUse;
use tessari_oauth_types::{TenantId, Timestamp};

use super::repository::AssertionRepository;
use crate::{Result, Tenancy, retry};

/// What a spend found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spent {
    /// This call spent the assertion; the client is authenticated.
    Fresh,
    /// The assertion had been presented before — a replay, refused as `invalid_client`.
    Replayed,
}

/// Spent client assertions.
#[derive(Clone)]
pub struct AssertionService {
    repository: Arc<dyn AssertionRepository>,
    tenancy: Tenancy,
}

/// The record's key: the client's length first, so no client id containing the separator can name another
/// client's `jti`.
fn key(assertion: &AssertionUse) -> String {
    let client = assertion.client_id.as_str();
    format!("{}:{client}:{}", client.len(), assertion.jti)
}

/// How long to remember the assertion, in seconds: until it can no longer be accepted, which is its expiry plus the
/// clock skew allowed; at least one second, the shortest expiry the store writes.
fn remember_for(assertion: &AssertionUse, now: Timestamp) -> u64 {
    assertion
        .expires_at
        .unix_secs()
        .saturating_add(CLOCK_SKEW_SECS)
        .saturating_sub(now.unix_secs())
        .max(1)
}

impl AssertionService {
    pub(crate) fn new(repository: Arc<dyn AssertionRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Spend `assertion` in `tenant` at `now`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or answers in a shape this crate cannot read.
    pub async fn spend(
        &self,
        tenant: &TenantId,
        assertion: &AssertionUse,
        now: Timestamp,
    ) -> Result<Spent> {
        let place = self.tenancy.place(tenant)?;
        let key = key(assertion);
        let seconds = remember_for(assertion, now);
        let recorded = retry::bounded(ASSERTION_SPEND_ATTEMPTS, retry::on_store_retry, || {
            self.repository.record_if_absent(&place, &key, seconds)
        })
        .await?;
        Ok(if recorded {
            Spent::Fresh
        } else {
            Spent::Replayed
        })
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
