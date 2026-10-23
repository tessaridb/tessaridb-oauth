//! Sign-in failures: counted per key in the region's counters, and a hold the store ends by itself.
//!
//! A failure adds one to its key's count, which lives the memory window from the key's first failure. Once the count
//! is past the key's free failures, a hold is written beside it (the instant it ends, under an expiry of the same
//! length), so the store itself retires the hold and no hold can outlive its cap: nothing here is a lockout. A
//! sign-in asks for the longest hold of its keys before it verifies anything. The counters are shared by every
//! server process counting into the region, so running more processes does not multiply an attacker's attempts, and
//! a write the store answers `retry` is made again, so simultaneous failures are each counted.

use tessari_oauth_constants::{SIGNIN_MEMORY_SECS, THROTTLE_WRITE_ATTEMPTS};
use tessari_oauth_core::signin::{SigninKey, hold_secs};
use tessari_oauth_types::Timestamp;

use super::ThrottleService;
use super::model::Counters;
use crate::{Error, Result, retry};

/// The name of a kind of key inside a counter's key.
const fn kind(key: SigninKey) -> &'static str {
    match key {
        SigninKey::Account => "account",
        SigninKey::Source => "source",
        SigninKey::Pair => "pair",
    }
}

/// The failure count of a key. The kind is a fixed word holding no `:`, so the value, which may, comes last and
/// two keys cannot share a counter, nor a sign-in key a request counter, whose group names never start `signin`.
fn count_key(key: SigninKey, value: &str) -> String {
    format!("signin:{}:{value}", kind(key))
}

/// The hold of a key, apart from its count.
fn hold_key(key: SigninKey, value: &str) -> String {
    format!("hold:{}:{value}", kind(key))
}

impl ThrottleService {
    /// Count a failed sign-in against each of `keys` (a kind and the value the ceremony names it by) at `now`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or answers in a shape this crate cannot read.
    pub async fn signin_failed(&self, keys: &[(SigninKey, &str)], now: Timestamp) -> Result<()> {
        let place = self.tenancy.throttle();
        for &(key, value) in keys {
            let counted = count_key(key, value);
            let failures = retry::bounded(THROTTLE_WRITE_ATTEMPTS, retry::on_store_retry, || {
                self.repository
                    .count(place, Counters::Signins, &counted, SIGNIN_MEMORY_SECS)
            })
            .await?;
            let hold = hold_secs(key, failures);
            if hold > 0 {
                let until = now.unix_secs().saturating_add(hold);
                self.lengthen(&hold_key(key, value), until, hold).await?;
            }
        }
        Ok(())
    }

    /// Make the hold under `key` end no earlier than `until`, living `seconds`. Simultaneous failures write one hold;
    /// each writes only over the value it read, so a later write of a shorter hold never replaces a longer one.
    async fn lengthen(&self, key: &str, until: u64, seconds: u64) -> Result<()> {
        let place = self.tenancy.throttle();
        for _ in 0..THROTTLE_WRITE_ATTEMPTS {
            let held = self.repository.held_until(place, key).await?;
            if held.is_some_and(|held| held >= until) {
                return Ok(());
            }
            let written = retry::bounded(THROTTLE_WRITE_ATTEMPTS, retry::on_store_retry, || {
                self.repository.hold(place, key, held, until, seconds)
            })
            .await?;
            if written {
                return Ok(());
            }
        }
        Err(Error::Unreadable {
            record: "sign-in hold",
            reason: format!("still moving after {THROTTLE_WRITE_ATTEMPTS} attempts"),
        })
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
        for key in [
            count_key(SigninKey::Account, account),
            hold_key(SigninKey::Account, account),
        ] {
            retry::bounded(THROTTLE_WRITE_ATTEMPTS, retry::on_store_retry, || {
                self.repository.forget(place, &key)
            })
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "signin_tests.rs"]
mod tests;
