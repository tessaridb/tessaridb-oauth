//! Signing algorithms this server accepts, and the public keys clients register for them (RFC 7517, RFC 8037).

use ring::signature::{self, UnparsedPublicKey};
use serde::Deserialize;
use tessari_oauth_types::base64url;

use super::JoseError;

/// Length of an Ed25519 public key and of each P-256 coordinate, in bytes.
const KEY_COMPONENT_LEN: usize = 32;

/// The SEC 1 tag of an uncompressed elliptic-curve point.
const UNCOMPRESSED_POINT: u8 = 0x04;

/// A signature algorithm this server accepts. Only elliptic curves: small signatures and no padding history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Ed25519 (RFC 8037).
    EdDsa,
    /// ECDSA over P-256 with SHA-256 (RFC 7518 §3.4).
    Es256,
}

impl Algorithm {
    /// The algorithm's name in the JOSE registry, as an `alg` header writes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
        }
    }
}

/// A registered public key, bound to the one algorithm it verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    kid: Option<String>,
    algorithm: Algorithm,
    /// The raw key: 32 bytes for Ed25519, an uncompressed SEC 1 point for P-256.
    bytes: Vec<u8>,
}

/// The JWK members read here; every other member is ignored. `d` is read only to refuse a private key.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    d: Option<String>,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
}

impl VerifyingKey {
    /// Read a public JWK as a key for `algorithm`.
    ///
    /// # Errors
    ///
    /// [`JoseError::KeyRefused`] for anything but a public signing key of `algorithm`'s curve: a private key, a key
    /// for encryption, another key type or curve, a missing or wrong-length coordinate, or an `alg` member naming
    /// another algorithm.
    pub fn from_jwk(json: &str, algorithm: Algorithm) -> Result<Self, JoseError> {
        let jwk: Jwk = serde_json::from_str(json).map_err(|_| JoseError::KeyRefused)?;
        let public_signing = jwk.d.is_none()
            && jwk.usage.as_deref().is_none_or(|usage| usage == "sig")
            && jwk.alg.as_deref().is_none_or(|alg| alg == algorithm.name());
        if !public_signing {
            return Err(JoseError::KeyRefused);
        }
        let bytes = match (algorithm, jwk.kty.as_str(), jwk.crv.as_deref()) {
            (Algorithm::EdDsa, "OKP", Some("Ed25519")) => component(jwk.x.as_deref())?,
            (Algorithm::Es256, "EC", Some("P-256")) => {
                let mut point = vec![UNCOMPRESSED_POINT];
                point.extend(component(jwk.x.as_deref())?);
                point.extend(component(jwk.y.as_deref())?);
                point
            }
            _ => return Err(JoseError::KeyRefused),
        };
        Ok(Self {
            kid: jwk.kid,
            algorithm,
            bytes,
        })
    }

    /// The key's id, when it was registered with one.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The algorithm this key verifies.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Whether `signature` signs `message` under this key.
    pub(super) fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        let scheme: &dyn signature::VerificationAlgorithm = match self.algorithm {
            Algorithm::EdDsa => &signature::ED25519,
            Algorithm::Es256 => &signature::ECDSA_P256_SHA256_FIXED,
        };
        UnparsedPublicKey::new(scheme, &self.bytes)
            .verify(message, signature)
            .is_ok()
    }
}

/// One 32-byte key component in base64url.
fn component(encoded: Option<&str>) -> Result<Vec<u8>, JoseError> {
    let bytes = encoded
        .and_then(|text| base64url::decode(text).ok())
        .ok_or(JoseError::KeyRefused)?;
    if bytes.len() != KEY_COMPONENT_LEN {
        return Err(JoseError::KeyRefused);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "key_tests.rs"]
mod tests;
