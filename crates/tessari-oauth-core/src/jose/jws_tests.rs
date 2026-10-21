use tessari_oauth_types::base64url;

use super::verify;
use crate::jose::{Algorithm, JoseError, VerifyingKey};

/// RFC 8037 §A.4: Ed25519 over the payload "Example of Ed25519 signing".
const ED25519_JWS: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
const ED25519_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

/// RFC 7515 §A.3: ES256 over the "joe" claims.
const ES256_JWS: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
const ES256_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

fn key(jwk: &str, algorithm: Algorithm) -> VerifyingKey {
    VerifyingKey::from_jwk(jwk, algorithm).expect("an RFC key")
}

fn with_kid(jwk: &str, kid: &str) -> String {
    jwk.replacen('{', &format!(r#"{{"kid":"{kid}","#), 1)
}

/// The same JWS with one segment replaced.
fn replaced(jws: &str, segment: usize, value: &str) -> String {
    let mut parts: Vec<&str> = jws.split('.').collect();
    if let Some(slot) = parts.get_mut(segment) {
        *slot = value;
    }
    parts.join(".")
}

#[test]
fn the_rfc_ed25519_and_es256_examples_verify_and_return_their_payloads() {
    assert_eq!(
        verify(
            ED25519_JWS,
            Algorithm::EdDsa,
            &[key(ED25519_JWK, Algorithm::EdDsa)]
        )
        .map(|verified| (verified.typ, verified.payload)),
        Ok((None, b"Example of Ed25519 signing".to_vec()))
    );
    let verified = verify(
        ES256_JWS,
        Algorithm::Es256,
        &[key(ES256_JWK, Algorithm::Es256)],
    )
    .expect("RFC 7515 A.3 verifies");
    assert!(verified.payload.starts_with(br#"{"iss":"joe""#));
}

#[test]
fn the_algorithm_comes_from_configuration_and_a_header_naming_another_is_refused() {
    let es256 = [key(ES256_JWK, Algorithm::Es256)];
    assert_eq!(
        verify(ED25519_JWS, Algorithm::Es256, &es256),
        Err(JoseError::AlgorithmNotAllowed)
    );
    for header in [
        r#"{"alg":"none"}"#,
        r#"{"alg":"HS256"}"#,
        r#"{"alg":"es256"}"#,
    ] {
        let forged = replaced(ES256_JWS, 0, &base64url::encode(header.as_bytes()));
        assert_eq!(
            verify(&forged, Algorithm::Es256, &es256),
            Err(JoseError::AlgorithmNotAllowed),
            "{header}"
        );
    }
}

#[test]
fn a_critical_header_is_refused_because_nothing_here_understands_one() {
    let header = base64url::encode(br#"{"alg":"ES256","crit":["exp"],"exp":1}"#);
    assert_eq!(
        verify(
            &replaced(ES256_JWS, 0, &header),
            Algorithm::Es256,
            &[key(ES256_JWK, Algorithm::Es256)]
        ),
        Err(JoseError::CriticalHeader)
    );
}

#[test]
fn the_key_is_found_by_kid_among_the_registered_keys_or_not_at_all() {
    let header = base64url::encode(br#"{"alg":"ES256","kid":"other"}"#);
    let named = replaced(ES256_JWS, 0, &header);
    let registered = [key(&with_kid(ES256_JWK, "k1"), Algorithm::Es256)];
    assert_eq!(
        verify(&named, Algorithm::Es256, &registered),
        Err(JoseError::UnknownKey)
    );
    let two = [
        key(&with_kid(ES256_JWK, "k1"), Algorithm::Es256),
        key(&with_kid(ES256_JWK, "k2"), Algorithm::Es256),
    ];
    assert_eq!(
        verify(ES256_JWS, Algorithm::Es256, &two),
        Err(JoseError::UnknownKey),
        "no kid and two candidates: no guessing"
    );
    assert_eq!(
        verify(ES256_JWS, Algorithm::Es256, &[]),
        Err(JoseError::UnknownKey)
    );
}

#[test]
fn a_changed_payload_or_signature_does_not_verify() {
    let ed = [key(ED25519_JWK, Algorithm::EdDsa)];
    let es = [key(ES256_JWK, Algorithm::Es256)];
    let payload = base64url::encode(b"Example of Ed25519 signinG");
    assert_eq!(
        verify(&replaced(ED25519_JWS, 1, &payload), Algorithm::EdDsa, &ed),
        Err(JoseError::BadSignature)
    );
    let signature = ES256_JWS
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .replacen('D', "E", 1);
    assert_eq!(
        verify(&replaced(ES256_JWS, 2, &signature), Algorithm::Es256, &es),
        Err(JoseError::BadSignature)
    );
}

#[test]
fn anything_but_three_well_formed_segments_is_malformed() {
    let es = [key(ES256_JWK, Algorithm::Es256)];
    for jws in [
        "",
        "a.b",
        "a.b.c.d",
        &format!("{ES256_JWS}."),
        &replaced(ES256_JWS, 0, "e30="),
        &replaced(ES256_JWS, 0, &base64url::encode(b"not json")),
    ] {
        assert_eq!(
            verify(jws, Algorithm::Es256, &es),
            Err(JoseError::Malformed),
            "{jws:?}"
        );
    }
}
