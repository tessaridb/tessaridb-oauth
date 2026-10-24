//! A software authenticator for the tests: it makes credentials and signs assertions exactly as the specification
//! lays them out, so every check can be exercised with a response that differs from a good one in one field.

use coset::iana::{self, EnumI64};
use coset::{CborSerializable, CoseKeyBuilder, cbor::Value};
use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RSA_PKCS1_SHA256,
    RsaKeyPair,
};
use tessari_oauth_types::base64url;

pub(super) const RP_ID: &str = "id.example.com";
pub(super) const ORIGIN: &str = "https://id.example.com";
pub(super) const CHALLENGE: &[u8] = b"a challenge of thirty-two bytes!";

/// User present.
pub(super) const UP: u8 = 0x01;
/// User verified.
pub(super) const UV: u8 = 0x04;
/// Backup eligible.
pub(super) const BE: u8 = 0x08;
/// Attested credential data included.
pub(super) const AT: u8 = 0x40;

/// A credential's private key.
pub(super) enum Signer {
    Ed25519(Ed25519KeyPair),
    P256(EcdsaKeyPair),
    Rs256(RsaKeyPair),
}

/// A 2048-bit RSA key for the tests only (PKCS#8 DER): `ring` verifies RSA but cannot make a key.
const RS256_TEST_KEY: &[u8] = include_bytes!("testdata/rs256-test-key.pk8");

impl Signer {
    pub(super) fn ed25519() -> Self {
        let random = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&random).expect("a key");
        Self::Ed25519(Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("a key"))
    }

    pub(super) fn p256() -> Self {
        let random = SystemRandom::new();
        let document =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).expect("a key");
        Self::P256(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
                .expect("a key"),
        )
    }

    pub(super) fn rs256() -> Self {
        Self::Rs256(RsaKeyPair::from_pkcs8(RS256_TEST_KEY).expect("a key"))
    }

    /// The public key as the COSE key an authenticator sends.
    pub(super) fn cose_key(&self) -> Vec<u8> {
        let key = match self {
            Self::Ed25519(pair) => CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv.to_i64(),
                    Value::from(iana::EllipticCurve::Ed25519.to_i64()),
                )
                .param(
                    iana::OkpKeyParameter::X.to_i64(),
                    Value::Bytes(pair.public_key().as_ref().to_vec()),
                )
                .algorithm(iana::Algorithm::EdDSA)
                .build(),
            Self::P256(pair) => {
                let point = pair.public_key().as_ref();
                CoseKeyBuilder::new_ec2_pub_key(
                    iana::EllipticCurve::P_256,
                    point[1..33].to_vec(),
                    point[33..65].to_vec(),
                )
                .algorithm(iana::Algorithm::ES256)
                .build()
            }
            Self::Rs256(pair) => {
                let (modulus, exponent) = rsa_components(pair.public().as_ref());
                CoseKeyBuilder::new()
                    .key_type(iana::KeyType::RSA)
                    .param(iana::RsaKeyParameter::N.to_i64(), Value::Bytes(modulus))
                    .param(iana::RsaKeyParameter::E.to_i64(), Value::Bytes(exponent))
                    .algorithm(iana::Algorithm::RS256)
                    .build()
            }
        };
        key.to_vec().expect("encodes")
    }

    pub(super) fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(pair) => pair.sign(message).as_ref().to_vec(),
            Self::P256(pair) => pair
                .sign(&SystemRandom::new(), message)
                .expect("signs")
                .as_ref()
                .to_vec(),
            Self::Rs256(pair) => {
                let mut signature = vec![0_u8; pair.public().modulus_len()];
                pair.sign(
                    &RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    message,
                    &mut signature,
                )
                .expect("signs");
                signature
            }
        }
    }
}

/// The modulus and exponent of a DER `RSAPublicKey` (RFC 8017 §A.1.1), without the sign byte DER puts ahead of a
/// modulus whose top bit is set.
fn rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn element(input: &[u8]) -> (&[u8], &[u8]) {
        let (length, header) = match input[1] {
            short @ ..=0x7f => (usize::from(short), 2),
            0x81 => (usize::from(input[2]), 3),
            _ => (usize::from(u16::from_be_bytes([input[2], input[3]])), 4),
        };
        input[header..].split_at(length)
    }
    let (sequence, _) = element(der);
    let (modulus, rest) = element(sequence);
    let (exponent, _) = element(rest);
    let strip = |integer: &[u8]| integer.strip_prefix(&[0]).unwrap_or(integer).to_vec();
    (strip(modulus), strip(exponent))
}

/// The client data a browser sends for `ceremony` (`webauthn.create` or `webauthn.get`).
pub(super) fn client_data(ceremony: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ceremony}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        base64url::encode(challenge)
    )
    .into_bytes()
}

/// Authenticator data: the relying-party id's hash, the flags, the counter, and — with `credential` — the attested
/// credential data (an all-zero AAGUID, the id, the COSE key).
pub(super) fn authenticator_data(
    rp_id: &str,
    flags: u8,
    count: u32,
    credential: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let mut data = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
    data.push(flags);
    data.extend_from_slice(&count.to_be_bytes());
    if let Some((id, key)) = credential {
        data.extend_from_slice(&[0_u8; 16]);
        data.extend_from_slice(&u16::try_from(id.len()).expect("short").to_be_bytes());
        data.extend_from_slice(id);
        data.extend_from_slice(key);
    }
    data
}

/// An attestation object of format `none` carrying `authenticator_data`.
pub(super) fn attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
    Value::Map(vec![
        (
            Value::Text("fmt".to_owned()),
            Value::Text("none".to_owned()),
        ),
        (Value::Text("attStmt".to_owned()), Value::Map(Vec::new())),
        (
            Value::Text("authData".to_owned()),
            Value::Bytes(authenticator_data.to_vec()),
        ),
    ])
    .to_vec()
    .expect("encodes")
}

/// The signature an authenticator makes over `authenticator_data` and the hash of `client_data`.
pub(super) fn assertion_signature(
    signer: &Signer,
    authenticator_data: &[u8],
    client_data: &[u8],
) -> Vec<u8> {
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(digest(&SHA256, client_data).as_ref());
    signer.sign(&message)
}
