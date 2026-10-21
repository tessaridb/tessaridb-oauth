use tessari_oauth_constants::{
    JWKS_MAX_AGE_SECS, SIGNED_TOKEN_MAX_TTL_SECS, SIGNING_KEY_LIFETIME_SECS,
};
use tessari_oauth_types::{KeyThumbprint, Timestamp};

use super::{KeyPlan, KeyRecord, plan};

const T0: u64 = 1_800_000_000;

/// A thumbprint-shaped id whose first letter tells the keys apart.
fn kid(letter: char) -> KeyThumbprint {
    KeyThumbprint::parse(format!("{letter}{}", "A".repeat(42))).expect("43 characters")
}

fn key(letter: char, created: u64) -> KeyRecord {
    KeyRecord {
        kid: kid(letter),
        created_at: Timestamp::from_unix_secs(created),
        compromised: false,
    }
}

fn at(records: &[KeyRecord], now: u64) -> KeyPlan {
    plan(records, Timestamp::from_unix_secs(now))
}

#[test]
fn with_no_key_the_rule_asks_for_one_and_nothing_signs() {
    let decided = at(&[], T0);
    assert_eq!(decided.signing, None);
    assert!(decided.generate);
    assert!(decided.published.is_empty());
}

#[test]
fn a_first_key_signs_at_once_and_says_it_has_not_waited() {
    let decided = at(&[key('a', T0)], T0);
    assert_eq!(decided.signing, Some(kid('a')));
    assert!(decided.signing_unwaited);
    assert!(!decided.generate);
    let waited = at(&[key('a', T0)], T0 + JWKS_MAX_AGE_SECS);
    assert!(!waited.signing_unwaited);
}

#[test]
fn a_new_key_is_published_at_once_but_signs_only_after_the_jwks_max_age() {
    let keys = [key('a', T0), key('b', T0 + 1_000)];
    let early = at(&keys, T0 + 1_000 + JWKS_MAX_AGE_SECS - 1);
    assert_eq!(early.signing, Some(kid('a')));
    assert_eq!(early.published, vec![kid('a'), kid('b')]);
    let ready = at(&keys, T0 + 1_000 + JWKS_MAX_AGE_SECS);
    assert_eq!(ready.signing, Some(kid('b')));
}

#[test]
fn a_successor_is_asked_for_early_enough_to_have_waited_when_it_is_needed() {
    let due = T0 + SIGNING_KEY_LIFETIME_SECS - JWKS_MAX_AGE_SECS;
    assert!(!at(&[key('a', T0)], due - 1).generate);
    assert!(at(&[key('a', T0)], due).generate);
    assert!(
        !at(&[key('a', T0), key('b', due)], due).generate,
        "a successor already exists"
    );
}

#[test]
fn a_superseded_key_stays_published_for_the_longest_token_it_signed_then_retires() {
    let keys = [key('a', T0), key('b', T0 + 1_000)];
    let switched = T0 + 1_000 + JWKS_MAX_AGE_SECS;
    let kept = at(&keys, switched + SIGNED_TOKEN_MAX_TTL_SECS - 1);
    assert_eq!(kept.published, vec![kid('a'), kid('b')]);
    assert!(kept.retire.is_empty());
    let gone = at(&keys, switched + SIGNED_TOKEN_MAX_TTL_SECS);
    assert_eq!(gone.published, vec![kid('b')]);
    assert_eq!(gone.retire, vec![kid('a')]);
}

#[test]
fn a_compromised_key_is_withdrawn_at_once() {
    let mut compromised = key('b', T0 + 1_000);
    compromised.compromised = true;
    let keys = [key('a', T0), compromised];
    let decided = at(&keys, T0 + 1_000 + JWKS_MAX_AGE_SECS);
    assert_eq!(decided.signing, Some(kid('a')));
    assert_eq!(decided.published, vec![kid('a')]);
    assert_eq!(decided.retire, vec![kid('b')]);
    let mut only = key('a', T0);
    only.compromised = true;
    let alone = at(&[only], T0 + 10);
    assert_eq!(alone.signing, None);
    assert!(alone.generate);
}
