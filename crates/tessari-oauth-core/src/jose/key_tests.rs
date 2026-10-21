use super::{Algorithm, VerifyingKey};
use crate::jose::JoseError;

const ED25519_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const P256_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const P256_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

#[test]
fn public_keys_of_both_curves_are_accepted_with_their_kid() {
    let ed = VerifyingKey::from_jwk(
        &format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED25519_X}","kid":"a","use":"sig"}}"#),
        Algorithm::EdDsa,
    )
    .expect("Ed25519 public key");
    assert_eq!(ed.kid(), Some("a"));
    let ec = VerifyingKey::from_jwk(
        &format!(r#"{{"kty":"EC","crv":"P-256","x":"{P256_X}","y":"{P256_Y}","alg":"ES256"}}"#),
        Algorithm::Es256,
    )
    .expect("P-256 public key");
    assert_eq!(ec.kid(), None);
}

#[test]
fn a_key_that_is_not_a_public_signing_key_of_the_configured_algorithm_is_refused() {
    for (jwk, algorithm) in [
        // a private key registered as if public
        (
            format!(
                r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED25519_X}","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}}"#
            ),
            Algorithm::EdDsa,
        ),
        // the curve of the other algorithm
        (
            format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{ED25519_X}"}}"#),
            Algorithm::Es256,
        ),
        // a coordinate of the wrong length
        (
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{P256_X}","y":"AAAA"}}"#),
            Algorithm::Es256,
        ),
        // a missing coordinate
        (
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{P256_X}"}}"#),
            Algorithm::Es256,
        ),
        // a curve not offered
        (
            format!(r#"{{"kty":"EC","crv":"P-384","x":"{P256_X}","y":"{P256_Y}"}}"#),
            Algorithm::Es256,
        ),
        // a key type not offered
        (
            r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#.to_owned(),
            Algorithm::Es256,
        ),
        // an `alg` member disagreeing with configuration
        (
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{P256_X}","y":"{P256_Y}","alg":"ES384"}}"#),
            Algorithm::Es256,
        ),
        // an encryption key
        (
            format!(r#"{{"kty":"EC","crv":"P-256","x":"{P256_X}","y":"{P256_Y}","use":"enc"}}"#),
            Algorithm::Es256,
        ),
        // not a JWK at all
        ("[]".to_owned(), Algorithm::Es256),
    ] {
        assert_eq!(
            VerifyingKey::from_jwk(&jwk, algorithm).map(|_| ()),
            Err(JoseError::KeyRefused),
            "{jwk}"
        );
    }
}

#[test]
fn the_algorithms_are_named_as_the_jose_registry_names_them() {
    assert_eq!(Algorithm::EdDsa.name(), "EdDSA");
    assert_eq!(Algorithm::Es256.name(), "ES256");
}
