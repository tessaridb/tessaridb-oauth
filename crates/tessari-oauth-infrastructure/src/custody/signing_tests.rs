use ring::signature::{ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey, VerificationAlgorithm};
use serde::Deserialize;
use tessari_oauth_types::{Algorithm, KeyThumbprint, base64url};

use super::SigningKey;

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: Option<String>,
    kid: String,
    alg: String,
    #[serde(rename = "use")]
    usage: String,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

fn decoded(text: &str) -> Vec<u8> {
    base64url::decode(text).expect("base64url")
}

#[test]
fn a_generated_key_signs_what_its_published_jwk_verifies_and_is_named_by_its_thumbprint() {
    for algorithm in [Algorithm::EdDsa, Algorithm::Es256] {
        let (key, pkcs8) = SigningKey::generate(algorithm).expect("generated");
        let jwk: Jwk = serde_json::from_str(&key.public_jwk().expect("serialised")).expect("a JWK");
        let (scheme, raw, thumbprint): (&dyn VerificationAlgorithm, Vec<u8>, KeyThumbprint) =
            match algorithm {
                Algorithm::EdDsa => {
                    assert_eq!((jwk.kty.as_str(), jwk.crv.as_str()), ("OKP", "Ed25519"));
                    let x = decoded(&jwk.x);
                    (&ED25519, x.clone(), KeyThumbprint::of_ed25519(&x))
                }
                Algorithm::Es256 => {
                    assert_eq!((jwk.kty.as_str(), jwk.crv.as_str()), ("EC", "P-256"));
                    let (x, y) = (decoded(&jwk.x), decoded(jwk.y.as_deref().expect("y")));
                    let mut point = vec![0x04];
                    point.extend(&x);
                    point.extend(&y);
                    (
                        &ECDSA_P256_SHA256_FIXED,
                        point,
                        KeyThumbprint::of_p256(&x, &y),
                    )
                }
            };
        assert_eq!(
            (jwk.alg.as_str(), jwk.usage.as_str()),
            (algorithm.name(), "sig")
        );
        assert_eq!(jwk.kid, thumbprint.as_str());
        assert_eq!(key.kid(), &thumbprint);

        let compact = key
            .sign_compact("at+jwt", br#"{"sub":"x"}"#)
            .expect("signed");
        let (input, signature) = compact.rsplit_once('.').expect("three segments");
        let (header, payload) = input.split_once('.').expect("three segments");
        let header: Header = serde_json::from_slice(&decoded(header)).expect("a header");
        assert_eq!(
            (
                header.alg.as_str(),
                header.kid.as_str(),
                header.typ.as_str()
            ),
            (algorithm.name(), thumbprint.as_str(), "at+jwt")
        );
        assert_eq!(decoded(payload), br#"{"sub":"x"}"#);
        assert!(
            UnparsedPublicKey::new(scheme, &raw)
                .verify(input.as_bytes(), &decoded(signature))
                .is_ok(),
            "{algorithm:?}"
        );

        let reopened = SigningKey::from_pkcs8(algorithm, &pkcs8).expect("reopened");
        assert_eq!(reopened.kid(), key.kid());
    }
}

#[test]
fn two_generated_keys_differ_and_a_key_does_not_open_as_the_other_algorithm() {
    let (first, pkcs8) = SigningKey::generate(Algorithm::Es256).expect("generated");
    let (second, _) = SigningKey::generate(Algorithm::Es256).expect("generated");
    assert_ne!(first.kid(), second.kid());
    assert!(SigningKey::from_pkcs8(Algorithm::EdDsa, &pkcs8).is_err());
}
