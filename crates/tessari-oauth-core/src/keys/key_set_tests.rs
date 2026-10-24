use serde_json::Value;
use tessari_oauth_types::KeyThumbprint;

use super::{KeySetError, key_set};
use crate::keys::KeyPlan;

/// RFC 7638 §3.1 and RFC 9449 §6 thumbprints, and one more of the same shape.
const OLD: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
const NEW: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
const BURNT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

fn kid(raw: &str) -> KeyThumbprint {
    KeyThumbprint::parse(raw).expect("a thumbprint")
}

fn jwk(raw: &str) -> String {
    format!(
        r#"{{"kty":"OKP","crv":"Ed25519","x":"x-{raw}","kid":"{raw}","alg":"EdDSA","use":"sig"}}"#
    )
}

fn publishing(kids: &[&str]) -> KeyPlan {
    KeyPlan {
        signing: kids.last().map(|raw| kid(raw)),
        signing_unwaited: false,
        published: kids.iter().map(|raw| kid(raw)).collect(),
        generate: false,
        retire: Vec::new(),
    }
}

fn kids_of(document: &str) -> Vec<String> {
    let parsed: Value = serde_json::from_str(document).expect("JSON");
    parsed["keys"]
        .as_array()
        .expect("a keys array")
        .iter()
        .map(|key| key["kid"].as_str().expect("a kid").to_owned())
        .collect()
}

#[test]
fn the_key_set_holds_exactly_the_published_keys_in_the_plans_order() {
    let stored = [
        (kid(NEW), jwk(NEW)),
        (kid(BURNT), jwk(BURNT)),
        (kid(OLD), jwk(OLD)),
    ];
    let document = key_set(
        &publishing(&[OLD, NEW]),
        stored.iter().map(|(kid, jwk)| (kid, jwk.as_str())),
    )
    .expect("a key set");
    assert_eq!(kids_of(&document), [OLD, NEW]);
}

#[test]
fn a_stored_key_is_embedded_byte_for_byte() {
    let stored = [(kid(NEW), jwk(NEW))];
    let document = key_set(
        &publishing(&[NEW]),
        stored.iter().map(|(kid, jwk)| (kid, jwk.as_str())),
    )
    .expect("a key set");
    assert_eq!(document, format!(r#"{{"keys":[{}]}}"#, jwk(NEW)));
}

#[test]
fn a_published_key_without_a_stored_public_half_is_refused() {
    let stored = [(kid(OLD), jwk(OLD))];
    let refused = key_set(
        &publishing(&[OLD, NEW]),
        stored.iter().map(|(kid, jwk)| (kid, jwk.as_str())),
    );
    assert_eq!(refused, Err(KeySetError::MissingKey));
}

#[test]
fn a_stored_public_half_that_is_not_a_json_object_is_refused() {
    for bad in ["not json", r#"["a","list"]"#, r#""a string""#] {
        let stored = [(kid(NEW), bad.to_owned())];
        let refused = key_set(
            &publishing(&[NEW]),
            stored.iter().map(|(kid, jwk)| (kid, jwk.as_str())),
        );
        assert_eq!(refused, Err(KeySetError::NotAKey), "{bad}");
    }
}

#[test]
fn nothing_published_is_an_empty_key_set() {
    let document = key_set(&publishing(&[]), std::iter::empty()).expect("a key set");
    assert_eq!(document, r#"{"keys":[]}"#);
}
