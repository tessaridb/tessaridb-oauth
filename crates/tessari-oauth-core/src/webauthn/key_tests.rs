//! Which public keys a registration accepts: only a key that names the algorithm it is verified with, on the curve
//! or at the size that algorithm needs.

use super::authenticator::{
    AT, CHALLENGE, ORIGIN, RP_ID, UP, UV, attestation_object, authenticator_data, client_data,
};
use super::tests::{CREDENTIAL_ID, expected};
use super::{WebauthnRefused, register};

#[test]
fn a_registration_refuses_a_key_that_could_never_verify() {
    use coset::iana::{self, EnumI64 as _};
    use coset::{CborSerializable as _, CoseKeyBuilder, cbor::Value};

    let rsa_as = |modulus: Vec<u8>, algorithm: iana::Algorithm| {
        CoseKeyBuilder::new()
            .key_type(iana::KeyType::RSA)
            .param(iana::RsaKeyParameter::N.to_i64(), Value::Bytes(modulus))
            .param(
                iana::RsaKeyParameter::E.to_i64(),
                Value::Bytes(vec![1, 0, 1]),
            )
            .algorithm(algorithm)
            .build()
            .to_vec()
            .expect("encodes")
    };
    let rsa = |modulus: Vec<u8>| rsa_as(modulus, iana::Algorithm::RS256);
    let p256_as_es384 =
        CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![9; 32], vec![9; 32])
            .algorithm(iana::Algorithm::ES384)
            .build()
            .to_vec()
            .expect("encodes");
    let okp_on = |curve: iana::EllipticCurve| {
        CoseKeyBuilder::new_okp_key()
            .param(
                iana::OkpKeyParameter::Crv.to_i64(),
                Value::from(curve.to_i64()),
            )
            .param(iana::OkpKeyParameter::X.to_i64(), Value::Bytes(vec![9; 32]))
            .algorithm(iana::Algorithm::EdDSA)
            .build()
            .to_vec()
            .expect("encodes")
    };
    let ed25519_without_algorithm = CoseKeyBuilder::new_okp_key()
        .param(
            iana::OkpKeyParameter::Crv.to_i64(),
            Value::from(iana::EllipticCurve::Ed25519.to_i64()),
        )
        .param(iana::OkpKeyParameter::X.to_i64(), Value::Bytes(vec![9; 32]))
        .build()
        .to_vec()
        .expect("encodes");
    let short_ed25519 = CoseKeyBuilder::new_okp_key()
        .param(
            iana::OkpKeyParameter::Crv.to_i64(),
            Value::from(iana::EllipticCurve::Ed25519.to_i64()),
        )
        .param(iana::OkpKeyParameter::X.to_i64(), Value::Bytes(vec![9; 31]))
        .algorithm(iana::Algorithm::EdDSA)
        .build()
        .to_vec()
        .expect("encodes");
    let cases = [
        ("a 1024-bit RSA modulus", rsa(vec![0xc3; 128])),
        (
            "a 2047-bit RSA modulus",
            rsa([&[0x7f][..], &[0xc3; 255]].concat()),
        ),
        ("an Ed25519 key one byte short", short_ed25519),
        (
            "an OKP key on another curve",
            okp_on(iana::EllipticCurve::X25519),
        ),
        (
            "an RSA key declaring PSS",
            rsa_as(vec![0xc3; 256], iana::Algorithm::PS256),
        ),
        ("a P-256 key declaring ES384", p256_as_es384),
        (
            "an Ed25519 key with no algorithm",
            ed25519_without_algorithm,
        ),
        (
            "an RSA key declaring ES256",
            rsa_as(vec![0xc3; 256], iana::Algorithm::ES256),
        ),
    ];
    let client = client_data("webauthn.create", CHALLENGE, ORIGIN);
    for (case, key) in cases {
        let data = authenticator_data(RP_ID, UP | UV | AT, 0, Some((CREDENTIAL_ID, &key)));
        assert_eq!(
            register(&client, &attestation_object(&data), &expected(true)),
            Err(WebauthnRefused::KeyNotAccepted),
            "{case}"
        );
    }
    let full = rsa([&[0x80][..], &[0xc3; 255]].concat());
    let data = authenticator_data(RP_ID, UP | UV | AT, 0, Some((CREDENTIAL_ID, &full)));
    assert!(
        register(&client, &attestation_object(&data), &expected(true)).is_ok(),
        "a 2048-bit modulus is the floor and is accepted"
    );
}
