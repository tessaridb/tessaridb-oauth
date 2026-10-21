//! A tenant signing key: generated here, opened here, and used here to sign; only its public half and its sealed
//! PKCS#8 form ever leave.

use std::fmt;

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use serde::Serialize;
use tessari_oauth_types::{Algorithm, KeyThumbprint, base64url};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Length of an Ed25519 public key and of each P-256 coordinate, in bytes.
const COMPONENT_LEN: usize = 32;

enum Pair {
    Ed25519(Ed25519KeyPair),
    P256(EcdsaKeyPair),
}

/// A signing key of one algorithm, named by the RFC 7638 thumbprint of its public key.
pub struct SigningKey {
    algorithm: Algorithm,
    kid: KeyThumbprint,
    pair: Pair,
    /// The public key's `x`, and `y` for P-256.
    x: Vec<u8>,
    y: Option<Vec<u8>>,
    random: SystemRandom,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// The public JWK as published in a key set (RFC 7517 §4).
#[derive(Serialize)]
struct PublicJwk<'a> {
    kty: &'static str,
    crv: &'static str,
    x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
    kid: &'a str,
    alg: &'static str,
    #[serde(rename = "use")]
    usage: &'static str,
}

/// The protected header this key signs under: its algorithm and `kid` always, and the object's type.
#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'a str,
}

const fn custody(reason: &'static str) -> Error {
    Error::Custody { reason }
}

impl SigningKey {
    /// Generate a key for `algorithm`, answering it with its PKCS#8 form to be sealed.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] when the system random source fails.
    pub fn generate(algorithm: Algorithm) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let random = SystemRandom::new();
        let document = match algorithm {
            Algorithm::EdDsa => Ed25519KeyPair::generate_pkcs8(&random),
            Algorithm::Es256 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
            }
        }
        .map_err(|_| custody("key generation failed"))?;
        let pkcs8 = Zeroizing::new(document.as_ref().to_vec());
        Ok((Self::from_pkcs8(algorithm, &pkcs8)?, pkcs8))
    }

    /// Open a key of `algorithm` from its PKCS#8 form.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] when the bytes are not a PKCS#8 key of `algorithm`.
    pub fn from_pkcs8(algorithm: Algorithm, pkcs8: &[u8]) -> Result<Self> {
        let random = SystemRandom::new();
        let not_a_key = || custody("not a PKCS#8 key of the configured algorithm");
        let (pair, x, y, kid) = match algorithm {
            Algorithm::EdDsa => {
                let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| not_a_key())?;
                let x = pair.public_key().as_ref().to_vec();
                let kid = KeyThumbprint::of_ed25519(&x);
                (Pair::Ed25519(pair), x, None, kid)
            }
            Algorithm::Es256 => {
                let pair =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &random)
                        .map_err(|_| not_a_key())?;
                // An uncompressed SEC 1 point: the tag byte, then x and y.
                let point = pair.public_key().as_ref();
                let (x, y) = point
                    .get(1..)
                    .and_then(|coordinates| coordinates.split_at_checked(COMPONENT_LEN))
                    .ok_or_else(not_a_key)?;
                let (x, y) = (x.to_vec(), y.to_vec());
                let kid = KeyThumbprint::of_p256(&x, &y);
                (Pair::P256(pair), x, Some(y), kid)
            }
        };
        Ok(Self {
            algorithm,
            kid,
            pair,
            x,
            y,
            random,
        })
    }

    /// The key's id: its RFC 7638 thumbprint, so the `kid` can never name two keys.
    #[must_use]
    pub const fn kid(&self) -> &KeyThumbprint {
        &self.kid
    }

    /// The algorithm the key signs with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The public half as a JWK for the key set.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] should serialisation fail.
    pub fn public_jwk(&self) -> Result<String> {
        let (kty, crv) = match self.algorithm {
            Algorithm::EdDsa => ("OKP", "Ed25519"),
            Algorithm::Es256 => ("EC", "P-256"),
        };
        serde_json::to_string(&PublicJwk {
            kty,
            crv,
            x: base64url::encode(&self.x),
            y: self.y.as_deref().map(base64url::encode),
            kid: self.kid.as_str(),
            alg: self.algorithm.name(),
            usage: "sig",
        })
        .map_err(|_| custody("the public key could not be written"))
    }

    /// Sign `claims` as a compact JWS of type `typ`.
    ///
    /// # Errors
    ///
    /// [`Error::Custody`] when the header cannot be written or the signer fails.
    pub fn sign_compact(&self, typ: &str, claims: &[u8]) -> Result<String> {
        let header = serde_json::to_vec(&Header {
            alg: self.algorithm.name(),
            kid: self.kid.as_str(),
            typ,
        })
        .map_err(|_| custody("the header could not be written"))?;
        let input = format!(
            "{}.{}",
            base64url::encode(&header),
            base64url::encode(claims)
        );
        let signature = match &self.pair {
            Pair::Ed25519(pair) => pair.sign(input.as_bytes()).as_ref().to_vec(),
            Pair::P256(pair) => pair
                .sign(&self.random, input.as_bytes())
                .map_err(|_| custody("signing failed"))?
                .as_ref()
                .to_vec(),
        };
        Ok(format!("{input}.{}", base64url::encode(&signature)))
    }
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;
