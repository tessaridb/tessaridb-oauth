use tessari_oauth_constants::{
    SIGNIN_FIRST_HOLD_SECS, SIGNIN_FREE_FAILURES_ACCOUNT, SIGNIN_FREE_FAILURES_PAIR,
    SIGNIN_FREE_FAILURES_SOURCE, SIGNIN_MAX_HOLD_ACCOUNT_SECS, SIGNIN_MAX_HOLD_PAIR_SECS,
    SIGNIN_MAX_HOLD_SOURCE_SECS,
};

use super::{SigninKey, hold_secs};

const KEYS: [(SigninKey, u64, u64); 3] = [
    (
        SigninKey::Account,
        SIGNIN_FREE_FAILURES_ACCOUNT,
        SIGNIN_MAX_HOLD_ACCOUNT_SECS,
    ),
    (
        SigninKey::Source,
        SIGNIN_FREE_FAILURES_SOURCE,
        SIGNIN_MAX_HOLD_SOURCE_SECS,
    ),
    (
        SigninKey::Pair,
        SIGNIN_FREE_FAILURES_PAIR,
        SIGNIN_MAX_HOLD_PAIR_SECS,
    ),
];

#[test]
fn a_key_with_free_failures_left_is_not_held() {
    for (key, free, _) in KEYS {
        for failures in 0..=free {
            assert_eq!(hold_secs(key, failures), 0, "{key:?} after {failures}");
        }
    }
}

#[test]
fn the_hold_doubles_with_each_further_failure_up_to_the_cap() {
    for (key, free, cap) in KEYS {
        assert_eq!(hold_secs(key, free + 1), SIGNIN_FIRST_HOLD_SECS, "{key:?}");
        assert_eq!(
            hold_secs(key, free + 2),
            SIGNIN_FIRST_HOLD_SECS * 2,
            "{key:?}"
        );
        assert_eq!(
            hold_secs(key, free + 3),
            SIGNIN_FIRST_HOLD_SECS * 4,
            "{key:?}"
        );
        let mut last = 0;
        for failures in free + 1..free + 40 {
            let hold = hold_secs(key, failures);
            assert!(
                hold >= last,
                "{key:?}: never shorter after a further failure"
            );
            assert!(hold <= cap, "{key:?}: never past the cap");
            last = hold;
        }
        assert_eq!(last, cap, "{key:?}: the cap is reached");
    }
}

#[test]
fn the_hold_ends_at_the_cap_however_many_failures_there_were() {
    for (key, _, cap) in KEYS {
        for failures in [64, 65, 1_000, u64::MAX] {
            assert_eq!(hold_secs(key, failures), cap, "{key:?} after {failures}");
        }
    }
}
