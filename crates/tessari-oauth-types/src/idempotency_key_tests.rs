use tessari_oauth_constants::{IDEMPOTENCY_KEY_MAX_LEN, IDEMPOTENCY_KEY_MIN_LEN};

use super::{IdempotencyKey, request_digest};
use crate::{Actor, Error, ServiceId, UserId};

fn operator(name: &str) -> Actor {
    Actor::Operator(UserId::parse(name).expect("a user id"))
}

#[test]
fn keys_of_the_allowed_length_and_alphabet_are_accepted() {
    for raw in [
        "a".repeat(IDEMPOTENCY_KEY_MIN_LEN),
        "Z".repeat(IDEMPOTENCY_KEY_MAX_LEN),
        "0f8fad5b-d9cb-469f-a165-70867728950e".to_owned(),
        "ops_2026_10_23_disable".to_owned(),
    ] {
        assert!(IdempotencyKey::parse(raw.clone()).is_ok(), "{raw}");
    }
}

#[test]
fn short_long_and_foreign_keys_are_refused() {
    for raw in [
        String::new(),
        "a".repeat(IDEMPOTENCY_KEY_MIN_LEN - 1),
        "a".repeat(IDEMPOTENCY_KEY_MAX_LEN + 1),
        "key with spaces in it".to_owned(),
        "key/with/slashes/in/it".to_owned(),
        "key\nwith-a-line-break".to_owned(),
        "klé-with-an-accent-x".to_owned(),
    ] {
        assert!(
            matches!(
                IdempotencyKey::parse(raw.clone()),
                Err(Error::Invalid {
                    field: "idempotency_key",
                    ..
                })
            ),
            "{raw:?}"
        );
    }
}

#[test]
fn the_record_is_the_operators_own() {
    let key = IdempotencyKey::parse("0f8fad5b-d9cb-469f").expect("a key");
    let mine = key.record_id(&operator("operator-1"));
    assert_eq!(mine, key.record_id(&operator("operator-1")), "stable");
    assert_ne!(mine, key.record_id(&operator("operator-2")), "per operator");
    let other = IdempotencyKey::parse("0f8fad5b-d9cb-469e").expect("a key");
    assert_ne!(mine, other.record_id(&operator("operator-1")), "per key");
    let service = Actor::Service(ServiceId::parse("operator-1").expect("a service id"));
    assert_ne!(
        mine,
        key.record_id(&service),
        "a service never shares an operator's record"
    );
    assert_eq!(mine.len(), 43, "an unpadded base64url SHA-256");
}

#[test]
fn a_body_is_remembered_by_its_digest() {
    assert_eq!(request_digest(b"{}"), request_digest(b"{}"));
    assert_ne!(request_digest(b"{}"), request_digest(b"{ }"));
    assert_eq!(
        request_digest(b""),
        "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
        "SHA-256 of nothing"
    );
}
