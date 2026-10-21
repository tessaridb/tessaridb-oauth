//! The replay service: spend a client assertion or a DPoP proof once.
//!
//! Single use is a concurrency property, so a spend is one conditional write that answers who won; nothing is read
//! first. A `retry` from the store is answered by asking again a bounded number of times. Should the first attempt
//! have landed after all, the retry is told the key exists and the presentation is refused as a replay — the client
//! signs a new one, and nothing is ever accepted twice. A store that does not answer is an error, never a spend, so
//! the caller refuses the request: the record fails closed.
//!
//! Both kinds share one space, so each key names its kind first. An assertion is keyed by its client — length first,
//! because a client id may contain the separator — and a proof by its key's thumbprint, which never does.

use std::sync::Arc;

use tessari_oauth_constants::{CLOCK_SKEW_SECS, REPLAY_SPEND_ATTEMPTS};
use tessari_oauth_core::assertion::AssertionUse;
use tessari_oauth_core::dpop::ProofUse;
use tessari_oauth_types::{TenantId, Timestamp};

use super::repository::ReplayRepository;
use crate::{Result, Tenancy, retry};

/// What a spend found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spent {
    /// This call spent it; the request may proceed.
    Fresh,
    /// It had been presented before — a replay, refused.
    Replayed,
}

/// Spent client assertions and DPoP proofs.
#[derive(Clone)]
pub struct ReplayService {
    repository: Arc<dyn ReplayRepository>,
    tenancy: Tenancy,
}

/// The record's key for a client assertion.
fn assertion_key(assertion: &AssertionUse) -> String {
    let client = assertion.client_id.as_str();
    format!("a:{}:{client}:{}", client.len(), assertion.jti)
}

/// The record's key for a DPoP proof.
fn proof_key(proof: &ProofUse) -> String {
    format!("p:{}:{}", proof.thumbprint.as_str(), proof.jti)
}

/// How long to remember something that can be accepted until `expires_at`, in seconds: until then plus the clock
/// skew allowed; at least one second, the shortest expiry the store writes.
fn remember_for(expires_at: Timestamp, now: Timestamp) -> u64 {
    expires_at
        .unix_secs()
        .saturating_add(CLOCK_SKEW_SECS)
        .saturating_sub(now.unix_secs())
        .max(1)
}

impl ReplayService {
    pub(crate) fn new(repository: Arc<dyn ReplayRepository>, tenancy: Tenancy) -> Self {
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
    pub async fn spend_assertion(
        &self,
        tenant: &TenantId,
        assertion: &AssertionUse,
        now: Timestamp,
    ) -> Result<Spent> {
        self.spend(
            tenant,
            &assertion_key(assertion),
            remember_for(assertion.expires_at, now),
        )
        .await
    }

    /// Spend `proof` in `tenant` at `now`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or answers in a shape this crate cannot read.
    pub async fn spend_proof(
        &self,
        tenant: &TenantId,
        proof: &ProofUse,
        now: Timestamp,
    ) -> Result<Spent> {
        self.spend(
            tenant,
            &proof_key(proof),
            remember_for(proof.expires_at, now),
        )
        .await
    }

    async fn spend(&self, tenant: &TenantId, key: &str, seconds: u64) -> Result<Spent> {
        let place = self.tenancy.place(tenant)?;
        let recorded = retry::bounded(REPLAY_SPEND_ATTEMPTS, retry::on_store_retry, || {
            self.repository.record_if_absent(&place, key, seconds)
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
