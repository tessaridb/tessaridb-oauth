//! How long a sign-in key is held after its failures: nothing while it has free failures left, then a hold that
//! doubles with each further failure up to the key's cap.
//!
//! A hold always ends by itself — there is no lockout an attacker could trigger to keep an owner out (a cap, never a
//! state that needs an operator). The three keys are counted apart because they catch different attacks: the
//! account key a guessing run against one account, the source key one address trying many accounts, the pair key the
//! same credential pair replayed.

use tessari_oauth_constants::{
    SIGNIN_FIRST_HOLD_SECS, SIGNIN_FREE_FAILURES_ACCOUNT, SIGNIN_FREE_FAILURES_PAIR,
    SIGNIN_FREE_FAILURES_SOURCE, SIGNIN_MAX_HOLD_ACCOUNT_SECS, SIGNIN_MAX_HOLD_PAIR_SECS,
    SIGNIN_MAX_HOLD_SOURCE_SECS,
};

// The hold anyone can impose on an account's owner is the shortest of the three.
const _: () = assert!(
    SIGNIN_MAX_HOLD_ACCOUNT_SECS < SIGNIN_MAX_HOLD_SOURCE_SECS
        && SIGNIN_MAX_HOLD_ACCOUNT_SECS < SIGNIN_MAX_HOLD_PAIR_SECS
);

/// What a sign-in failure is counted against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigninKey {
    /// The account the identifier names, known or not.
    Account,
    /// The address the request came from.
    Source,
    /// The identifier and password presented together.
    Pair,
}

/// Seconds `key` is held after `failures` failures in its memory window; 0 when it is not held.
#[must_use]
pub fn hold_secs(key: SigninKey, failures: u64) -> u64 {
    let (free, cap) = match key {
        SigninKey::Account => (SIGNIN_FREE_FAILURES_ACCOUNT, SIGNIN_MAX_HOLD_ACCOUNT_SECS),
        SigninKey::Source => (SIGNIN_FREE_FAILURES_SOURCE, SIGNIN_MAX_HOLD_SOURCE_SECS),
        SigninKey::Pair => (SIGNIN_FREE_FAILURES_PAIR, SIGNIN_MAX_HOLD_PAIR_SECS),
    };
    if failures <= free {
        return 0;
    }
    // The first failure past the free ones holds for the first hold; each one after doubles it.
    let doublings = failures.saturating_sub(free).saturating_sub(1);
    u32::try_from(doublings)
        .ok()
        .and_then(|doublings| 1_u64.checked_shl(doublings))
        .and_then(|factor| SIGNIN_FIRST_HOLD_SECS.checked_mul(factor))
        .map_or(cap, |hold| hold.min(cap))
}

#[cfg(test)]
#[path = "signin_tests.rs"]
mod tests;
