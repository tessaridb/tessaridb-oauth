use sha2::Digest as _;
use tessari_oauth_constants::{PKCE_VERIFIER_MAX_LEN, PKCE_VERIFIER_MIN_LEN};

use super::Challenge;
use crate::{Error, base64url};

/// RFC 7636 Appendix B, verbatim. An encoder that reproduces this pair is interoperable with every client that
/// follows the same document; one that does not is wrong in a way no local test could tell.
const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn refused_field(result: crate::Result<Challenge>) -> &'static str {
    match result {
        Err(Error::Invalid { field, .. }) => field,
        Ok(challenge) => panic!("expected a refusal, got {challenge:?}"),
    }
}

#[test]
fn the_client_half_reproduces_the_published_challenge() {
    // Pinned to the document's own pair: a `matches` agreeing with an `of` that is wrong in the same way would
    // prove internal consistency and nothing about RFC 7636.
    let built = Challenge::of(RFC_VERIFIER).expect("the published verifier is well formed");
    assert_eq!(built.as_str(), RFC_CHALLENGE);
}

#[test]
fn the_published_challenge_matches_the_published_verifier() {
    let challenge = Challenge::parse(RFC_CHALLENGE).expect("the RFC's own challenge parses");
    assert!(challenge.matches(RFC_VERIFIER));
}

#[test]
fn a_verifier_differing_in_one_character_does_not_match() {
    let challenge = Challenge::parse(RFC_CHALLENGE).expect("a challenge");
    // Same length, one character changed — so this measures the digest, not the length check in front of it.
    let nearly = RFC_VERIFIER.replacen('d', "D", 1);
    assert_ne!(nearly, RFC_VERIFIER, "control: the strings must differ");
    assert!(!challenge.matches(&nearly));
}

#[test]
fn a_verifier_below_the_floor_never_matches_its_own_challenge() {
    // The failure guarded here is a RIGHT answer: a client that chose `a` as its verifier would match a challenge
    // made from `a`, and the exchange would work while protecting nobody.
    let short = "a";
    let challenge = Challenge::parse(base64url::encode(&sha2::Sha256::digest(short.as_bytes())))
        .expect("a digest of anything is a well-shaped challenge");
    assert!(!challenge.matches(short));
}

#[test]
fn a_verifier_outside_the_grammar_is_refused_before_it_is_hashed() {
    for verifier in [
        "a".repeat(PKCE_VERIFIER_MIN_LEN - 1),
        "a".repeat(PKCE_VERIFIER_MAX_LEN + 1),
        "!".repeat(PKCE_VERIFIER_MIN_LEN),
    ] {
        assert_eq!(
            refused_field(Challenge::of(&verifier)),
            "code_verifier",
            "{verifier}"
        );
    }
}

#[test]
fn verifiers_at_both_length_bounds_are_accepted() {
    assert!(Challenge::of(&"a".repeat(PKCE_VERIFIER_MIN_LEN)).is_ok());
    assert!(Challenge::of(&"~".repeat(PKCE_VERIFIER_MAX_LEN)).is_ok());
}

#[test]
fn a_challenge_that_is_not_a_sha_256_digest_is_refused() {
    for raw in [
        "short".to_owned(),
        format!("{RFC_CHALLENGE}="),
        RFC_CHALLENGE.replacen('E', "+", 1),
        RFC_CHALLENGE[1..].to_owned(),
    ] {
        assert_eq!(
            refused_field(Challenge::parse(raw.clone())),
            "code_challenge",
            "{raw}"
        );
    }
}
