use ring::signature::Ed25519KeyPair;
use tessari_oauth_types::{ServiceId, Timestamp, base64url};

use super::{ServiceAssertionUse, ServiceRefusal, named_service, verify};
use crate::jose::{Algorithm, VerifyingKey};

/// RFC 8037 §A.1: the Ed25519 private key `d` and its public `x`.
const SEED: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
const PUBLIC_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
const ADMIN: &str = "https://admin.example/admin/acme";
const NOW: u64 = 1_800_000_000;
const HEADER: &str = r#"{"alg":"EdDSA","typ":"tessari-admin+jwt"}"#;

fn backend() -> ServiceId {
    ServiceId::parse("backend").expect("a service id")
}

fn key() -> VerifyingKey {
    VerifyingKey::from_jwk(PUBLIC_JWK, Algorithm::EdDsa).expect("RFC key")
}

fn signed(header: &str, claims: &str) -> String {
    let seed = base64url::decode(SEED).expect("RFC seed");
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).expect("RFC seed is a key");
    let input = format!(
        "{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(claims.as_bytes())
    );
    format!(
        "{input}.{}",
        base64url::encode(pair.sign(input.as_bytes()).as_ref())
    )
}

fn claims(iss: &str, aud: &str, exp: u64, jti: &str) -> String {
    format!(r#"{{"iss":"{iss}","sub":"{iss}","aud":{aud},"exp":{exp},"jti":"{jti}"}}"#)
}

fn good() -> String {
    claims("backend", &format!("{ADMIN:?}"), NOW + 30, "j-1")
}

fn check(compact: &str) -> Result<ServiceAssertionUse, ServiceRefusal> {
    verify(
        compact,
        &backend(),
        &key(),
        ADMIN,
        Timestamp::from_unix_secs(NOW),
    )
}

#[test]
fn a_fresh_assertion_for_this_company_names_its_service_and_what_to_spend() {
    assert_eq!(
        check(&signed(HEADER, &good())),
        Ok(ServiceAssertionUse {
            service: backend(),
            jti: "j-1".to_owned(),
            expires_at: Timestamp::from_unix_secs(NOW + 30),
        })
    );
    assert_eq!(named_service(&signed(HEADER, &good())), Some(backend()));
}

#[test]
fn only_the_admin_type_is_accepted_so_no_other_jwt_can_stand_in() {
    for header in [
        r#"{"alg":"EdDSA"}"#,
        r#"{"alg":"EdDSA","typ":"JWT"}"#,
        r#"{"alg":"EdDSA","typ":"client-authentication+jwt"}"#,
        r#"{"alg":"EdDSA","typ":"at+jwt"}"#,
    ] {
        assert_eq!(
            check(&signed(header, &good())),
            Err(ServiceRefusal::Type),
            "{header}"
        );
    }
}

#[test]
fn another_key_another_algorithm_or_none_is_a_bad_signature() {
    let none = format!(
        "{}.{}.",
        base64url::encode(br#"{"alg":"none","typ":"tessari-admin+jwt"}"#),
        base64url::encode(good().as_bytes())
    );
    let es256 = signed(r#"{"alg":"ES256","typ":"tessari-admin+jwt"}"#, &good());
    let mut tampered = signed(HEADER, &good());
    tampered.pop();
    tampered.push('A');
    for compact in [none, es256, tampered, "not.a.jws".to_owned()] {
        assert_eq!(check(&compact), Err(ServiceRefusal::Signature), "{compact}");
    }
}

#[test]
fn the_sole_audience_must_be_this_companys_admin_api() {
    for aud in [
        r#""https://admin.example/admin/initech""#.to_owned(),
        r#""https://id.example/acme""#.to_owned(),
        format!(r#"["{ADMIN}","https://elsewhere.example"]"#),
    ] {
        let compact = signed(HEADER, &claims("backend", &aud, NOW + 30, "j-1"));
        assert_eq!(check(&compact), Err(ServiceRefusal::Audience), "{aud}");
    }
    let listed = signed(
        HEADER,
        &claims("backend", &format!("[{ADMIN:?}]"), NOW + 30, "j-1"),
    );
    assert!(check(&listed).is_ok());
}

#[test]
fn the_issuer_and_subject_must_be_the_service_and_the_jti_present() {
    let aud = format!("{ADMIN:?}");
    let other = signed(HEADER, &claims("reports", &aud, NOW + 30, "j-1"));
    let blank = signed(HEADER, &claims("backend", &aud, NOW + 30, ""));
    let long = signed(HEADER, &claims("backend", &aud, NOW + 30, &"j".repeat(257)));
    for compact in [other, blank, long] {
        assert_eq!(check(&compact), Err(ServiceRefusal::Claims));
    }
}

#[test]
fn an_expired_or_long_lived_assertion_is_out_of_time() {
    let aud = format!("{ADMIN:?}");
    for exp in [NOW - 11, NOW + 71] {
        let compact = signed(HEADER, &claims("backend", &aud, exp, "j-1"));
        assert_eq!(check(&compact), Err(ServiceRefusal::Time), "exp {exp}");
    }
    let edge = signed(HEADER, &claims("backend", &aud, NOW + 70, "j-1"));
    assert!(
        check(&edge).is_ok(),
        "sixty seconds and the skew are allowed"
    );
}
