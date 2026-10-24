//! A credential's public key as a COSE key (RFC 9052 §7, RFC 9053), narrowed to the algorithms this relying party
//! accepts. The key names its own algorithm, which WebAuthn requires, and the pair must match exactly: an Ed25519
//! key for EdDSA, a P-256 point for ES256, an RSA key of at least 2048 bits for RS256. `ring` verifies, and
//! validates the point or the modulus while doing so.

use coset::cbor::Value;
use coset::iana::{self, EnumI64 as _};
use coset::{Algorithm, CborSerializable as _, CoseKey, KeyType, Label};
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents,
    UnparsedPublicKey, VerificationAlgorithm,
};
use tessari_oauth_constants::WEBAUTHN_RSA_MIN_MODULUS_BYTES;

use super::WebauthnRefused;

/// Bytes of an Ed25519 public key, and of each coordinate of a P-256 point.
const COORDINATE_BYTES: usize = 32;
/// The prefix of an uncompressed elliptic-curve point (SEC 1 §2.3.3).
const UNCOMPRESSED_POINT: u8 = 0x04;

/// A public key ready to verify an assertion.
pub(super) enum PublicKey {
    /// A key `ring` reads from one string of bytes: an Ed25519 key or an uncompressed P-256 point.
    Encoded {
        algorithm: &'static dyn VerificationAlgorithm,
        bytes: Vec<u8>,
    },
    /// An RSA key, verified as RSASSA-PKCS1-v1_5 with SHA-256 (RS256).
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
}

impl PublicKey {
    /// Check `signature` over `message`.
    pub(super) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), WebauthnRefused> {
        let verified = match self {
            Self::Encoded { algorithm, bytes } => {
                UnparsedPublicKey::new(*algorithm, bytes).verify(message, signature)
            }
            Self::Rsa { modulus, exponent } => RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            }
            .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature),
        };
        verified.map_err(|_| WebauthnRefused::SignatureInvalid)
    }
}

/// Read a COSE key this relying party accepts.
pub(super) fn parse(cose: &[u8]) -> Result<PublicKey, WebauthnRefused> {
    let refused = || WebauthnRefused::KeyNotAccepted;
    let key = CoseKey::from_slice(cose).map_err(|_| refused())?;
    match (&key.kty, &key.alg) {
        (
            KeyType::Assigned(iana::KeyType::OKP),
            Some(Algorithm::Assigned(iana::Algorithm::EdDSA)),
        ) => {
            curve(
                &key,
                iana::OkpKeyParameter::Crv.to_i64(),
                iana::EllipticCurve::Ed25519,
            )?;
            let x = coordinate(&key, iana::OkpKeyParameter::X.to_i64()).ok_or_else(refused)?;
            Ok(PublicKey::Encoded {
                algorithm: &ED25519,
                bytes: x.to_vec(),
            })
        }
        (
            KeyType::Assigned(iana::KeyType::EC2),
            Some(Algorithm::Assigned(iana::Algorithm::ES256)),
        ) => {
            curve(
                &key,
                iana::Ec2KeyParameter::Crv.to_i64(),
                iana::EllipticCurve::P_256,
            )?;
            let x = coordinate(&key, iana::Ec2KeyParameter::X.to_i64()).ok_or_else(refused)?;
            let y = coordinate(&key, iana::Ec2KeyParameter::Y.to_i64()).ok_or_else(refused)?;
            let mut bytes =
                Vec::with_capacity(COORDINATE_BYTES.saturating_mul(2).saturating_add(1));
            bytes.push(UNCOMPRESSED_POINT);
            bytes.extend_from_slice(x);
            bytes.extend_from_slice(y);
            Ok(PublicKey::Encoded {
                algorithm: &ECDSA_P256_SHA256_ASN1,
                bytes,
            })
        }
        (
            KeyType::Assigned(iana::KeyType::RSA),
            Some(Algorithm::Assigned(iana::Algorithm::RS256)),
        ) => {
            let integer = |label: iana::RsaKeyParameter| match param(&key, label.to_i64()) {
                Some(Value::Bytes(bytes)) if !bytes.is_empty() => Some(bytes.clone()),
                _ => None,
            };
            let modulus = integer(iana::RsaKeyParameter::N).ok_or_else(refused)?;
            if !at_least_2048_bits(&modulus) {
                return Err(refused());
            }
            Ok(PublicKey::Rsa {
                modulus,
                exponent: integer(iana::RsaKeyParameter::E).ok_or_else(refused)?,
            })
        }
        _ => Err(refused()),
    }
}

/// The value of parameter `label`.
fn param(key: &CoseKey, label: i64) -> Option<&Value> {
    key.params
        .iter()
        .find(|(name, _)| *name == Label::Int(label))
        .map(|(_, value)| value)
}

/// Refuse a key whose curve parameter is not `expected`.
fn curve(key: &CoseKey, label: i64, expected: iana::EllipticCurve) -> Result<(), WebauthnRefused> {
    if param(key, label) == Some(&Value::from(expected.to_i64())) {
        Ok(())
    } else {
        Err(WebauthnRefused::KeyNotAccepted)
    }
}

/// A coordinate parameter of exactly the length a 256-bit curve needs.
fn coordinate(key: &CoseKey, label: i64) -> Option<&[u8]> {
    match param(key, label) {
        Some(Value::Bytes(bytes)) if bytes.len() == COORDINATE_BYTES => Some(bytes),
        _ => None,
    }
}

/// Whether a big-endian modulus has at least the 2048 bits the verifier demands, leading zero bytes not counted.
fn at_least_2048_bits(modulus: &[u8]) -> bool {
    let start = modulus
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(modulus.len());
    let significant = modulus.get(start..).unwrap_or_default();
    match significant.len().cmp(&WEBAUTHN_RSA_MIN_MODULUS_BYTES) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal => significant.first().is_some_and(|&top| top >= 0x80),
        std::cmp::Ordering::Less => false,
    }
}
