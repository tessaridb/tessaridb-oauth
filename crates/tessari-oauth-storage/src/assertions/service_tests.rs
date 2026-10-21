use tessari_oauth_constants::CLOCK_SKEW_SECS;
use tessari_oauth_core::assertion::AssertionUse;
use tessari_oauth_types::{ClientId, Timestamp};

use super::{key, remember_for};

fn used(client: &str, jti: &str, expires_at: u64) -> AssertionUse {
    AssertionUse {
        client_id: ClientId::parse(client).expect("a client id"),
        jti: jti.to_owned(),
        expires_at: Timestamp::from_unix_secs(expires_at),
    }
}

#[test]
fn the_key_names_the_client_unambiguously_before_the_jti() {
    assert_eq!(key(&used("svc", "a-1", 0)), "3:svc:a-1");
    assert_ne!(key(&used("a b", "c", 0)), key(&used("a", "b c", 0)));
    assert_ne!(key(&used("a:1", "x", 0)), key(&used("a", "1:x", 0)));
}

#[test]
fn the_record_outlives_the_assertion_by_the_skew_and_is_never_shorter_than_a_second() {
    let now = Timestamp::from_unix_secs(1_000);
    assert_eq!(
        remember_for(&used("svc", "j", 1_060), now),
        60 + CLOCK_SKEW_SECS
    );
    assert_eq!(remember_for(&used("svc", "j", 1_000), now), CLOCK_SKEW_SECS);
    assert_eq!(remember_for(&used("svc", "j", 0), now), 1);
}
