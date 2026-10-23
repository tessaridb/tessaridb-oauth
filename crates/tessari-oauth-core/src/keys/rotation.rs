//! The rotation rule: from a tenant's key records and the time, which key signs, which are published, whether a
//! successor must be made, and which keys retire.
//!
//! The order is the whole point. A key is published the moment it exists but signs only once it has been published
//! for the key set's cache lifetime, so no verifier meets a `kid` it has not been able to fetch. A key that stopped
//! signing stays published for the longest token it could have signed. A compromised key is withdrawn at once,
//! accepting that what it signed stops verifying. A pure function, so the daemon that applies it is the only clock.

use tessari_oauth_constants::{
    JWKS_MAX_AGE_SECS, SIGNED_TOKEN_MAX_TTL_SECS, SIGNING_KEY_LIFETIME_SECS,
};
use tessari_oauth_types::{KeyThumbprint, Timestamp};

/// One signing key as the rule needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    /// The key's id.
    pub kid: KeyThumbprint,
    /// When it was made, which is when it was published.
    pub created_at: Timestamp,
    /// Whether it must be withdrawn at once.
    pub compromised: bool,
}

/// What the rule decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPlan {
    /// The key to sign with; `None` when there is no usable key.
    pub signing: Option<KeyThumbprint>,
    /// Whether that key signs before it has been published for the key set's cache lifetime — only when no key has
    /// waited, which on a tenant's first key is harmless and otherwise means rotation fell behind.
    pub signing_unwaited: bool,
    /// The keys the key set publishes, oldest first.
    pub published: Vec<KeyThumbprint>,
    /// Whether a successor must be generated now.
    pub generate: bool,
    /// The keys to retire: superseded long enough, or compromised.
    pub retire: Vec<KeyThumbprint>,
}

fn secs(at: Timestamp) -> u64 {
    at.unix_secs()
}

/// Decide for `records` at `now`.
#[must_use]
pub fn plan(records: &[KeyRecord], now: Timestamp) -> KeyPlan {
    let now = secs(now);
    let waited = |key: &KeyRecord| secs(key.created_at).saturating_add(JWKS_MAX_AGE_SECS) <= now;
    let mut live: Vec<&KeyRecord> = records.iter().filter(|key| !key.compromised).collect();
    live.sort_by_key(|key| key.created_at);
    let signer = live
        .iter()
        .rev()
        .find(|key| waited(key))
        .map(|key| (*key, false))
        // No key has waited yet: the one published longest is the likeliest to be in a verifier's cached set.
        .or_else(|| live.first().map(|key| (*key, true)));
    let Some((signing, signing_unwaited)) = signer else {
        return KeyPlan {
            signing: None,
            signing_unwaited: false,
            published: Vec::new(),
            generate: true,
            retire: compromised(records),
        };
    };
    // Every key older than the signer stopped signing no later than the signer started.
    let started = if signing_unwaited {
        secs(signing.created_at)
    } else {
        secs(signing.created_at).saturating_add(JWKS_MAX_AGE_SECS)
    };
    let superseded_long_enough = |key: &KeyRecord| {
        key.created_at < signing.created_at
            && now >= started.saturating_add(SIGNED_TOKEN_MAX_TTL_SECS)
    };
    let successor_exists = live.iter().any(|key| key.created_at > signing.created_at);
    let due = secs(signing.created_at)
        .saturating_add(SIGNING_KEY_LIFETIME_SECS)
        .saturating_sub(JWKS_MAX_AGE_SECS)
        <= now;
    let mut retire: Vec<KeyThumbprint> = live
        .iter()
        .filter(|key| superseded_long_enough(key))
        .map(|key| key.kid.clone())
        .collect();
    retire.extend(compromised(records));
    KeyPlan {
        signing: Some(signing.kid.clone()),
        signing_unwaited,
        published: live
            .iter()
            .filter(|key| !superseded_long_enough(key))
            .map(|key| key.kid.clone())
            .collect(),
        generate: due && !successor_exists,
        retire,
    }
}

fn compromised(records: &[KeyRecord]) -> Vec<KeyThumbprint> {
    records
        .iter()
        .filter(|key| key.compromised)
        .map(|key| key.kid.clone())
        .collect()
}

#[cfg(test)]
#[path = "rotation_tests.rs"]
mod tests;
