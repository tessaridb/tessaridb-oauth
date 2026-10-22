//! Sign-in failures: counted per key in the region's counters, and a hold the store ends by itself.
//!
//! A failure adds one to its key's count, which lives the memory window from the key's first failure. Once the count
//! is past the key's free failures, a hold is written beside it — the instant it ends, under an expiry of the same
//! length — so the store itself retires the hold and no hold can outlive its cap: nothing here is a lockout. A
//! sign-in asks for the longest hold of its keys before it verifies anything. The counters are shared by every
//! server process counting into the region, so running more processes does not multiply an attacker's attempts.

use tessari_oauth_constants::SIGNIN_MEMORY_SECS;
use tessari_oauth_core::signin::{SigninKey, hold_secs};
use tessari_oauth_types::Timestamp;

use super::ThrottleService;
use crate::Result;

/// The name of a kind of key inside a counter's key.
const fn kind(key: SigninKey) -> &'static str {
    match key {
        SigninKey::Account => "account",
        SigninKey::Source => "source",
        SigninKey::Pair => "pair",
    }
}

/// The failure count of a key. The kind is a fixed word holding no `:`, so the value — which may — comes last and
/// two keys cannot share a counter, nor a sign-in key a request counter, whose group names never start `signin`.
fn count_key(key: SigninKey, value: &str) -> String {
    format!("signin:{}:{value}", kind(key))
}

/// The hold of a key, apart from its count.
fn hold_key(key: SigninKey, value: &str) -> String {
    format!("hold:{}:{value}", kind(key))
}

impl ThrottleService {
    /// Count a failed sign-in against each of `keys` — a kind and the value the ceremony names it by — at `now`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or answers in a shape this crate cannot read.
    pub async fn signin_failed(&self, keys: &[(SigninKey, &str)], now: Timestamp) -> Result<()> {
        let place = self.tenancy.throttle();
        for &(key, value) in keys {
            let failures = self
                .repository
                .count(place, &count_key(key, value), SIGNIN_MEMORY_SECS)
                .await?;
            let hold = hold_secs(key, failures);
            if hold > 0 {
                let until = now.unix_secs().saturating_add(hold);
                self.repository
                    .hold(place, &hold_key(key, value), until, hold)
                    .await?;
            }
        }
        Ok(())
    }

    /// The seconds left on the longest hold of `keys` at `now`, or none when no key is held.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or answers in a shape this crate cannot read.
    pub async fn signin_hold(
        &self,
        keys: &[(SigninKey, &str)],
        now: Timestamp,
    ) -> Result<Option<u64>> {
        let place = self.tenancy.throttle();
        let mut longest = None;
        for &(key, value) in keys {
            let until = self
                .repository
                .held_until(place, &hold_key(key, value))
                .await?;
            let left = until.map_or(0, |until| until.saturating_sub(now.unix_secs()));
            if left > 0 && longest.is_none_or(|longest| left > longest) {
                longest = Some(left);
            }
        }
        Ok(longest)
    }

    /// Forget the failures and the hold of the account key `account` after a sign-in to it succeeded.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses.
    pub async fn signin_succeeded(&self, account: &str) -> Result<()> {
        let place = self.tenancy.throttle();
        self.repository
            .forget(place, &count_key(SigninKey::Account, account))
            .await?;
        self.repository
            .forget(place, &hold_key(SigninKey::Account, account))
            .await
    }
}
