//! A software Ed25519 authenticator for the sign-in tests: it holds one discoverable credential and signs
//! assertions laid out as Web Authentication Level 3 lays them out. The core crate's own test authenticator is private
//! to its unit tests, so the route tests carry this one; only Ed25519 is needed here.

use ring::digest::{SHA256, digest};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde_json::{Value, json};
use tessari_oauth_core::webauthn::Registered;
use tessari_oauth_types::base64url;

/// The relying party the fixture issuer names, and its origin.
pub(crate) const RP_ID: &str = "id.example.com";
pub(crate) const ORIGIN: &str = "https://id.example.com";

/// User present.
pub(crate) const UP: u8 = 0x01;
/// User verified.
pub(crate) const UV: u8 = 0x04;

pub(crate) struct Authenticator {
    pair: Ed25519KeyPair,
    pub(crate) credential_id: Vec<u8>,
}

impl Authenticator {
    pub(crate) fn new(credential_id: &[u8]) -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("readable");
        Self {
            pair,
            credential_id: credential_id.to_vec(),
        }
    }

    /// The credential as a registration would have stored it.
    pub(crate) fn registered(&self) -> Registered {
        // COSE_Key (RFC 9053): kty OKP, alg EdDSA, crv Ed25519, x.
        let mut key = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        key.extend_from_slice(self.pair.public_key().as_ref());
        Registered {
            credential_id: self.credential_id.clone(),
            public_key: key,
            sign_count: 0,
            user_verified: true,
            backup_eligible: true,
        }
    }

    /// The step's body for an assertion over `challenge` from `origin` with `flags` and `count`.
    pub(crate) fn assert(&self, challenge: &str, origin: &str, flags: u8, count: u32) -> Value {
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}"#
        );
        let mut data = digest(&SHA256, RP_ID.as_bytes()).as_ref().to_vec();
        data.push(flags);
        data.extend_from_slice(&count.to_be_bytes());
        let mut signed = data.clone();
        signed.extend_from_slice(digest(&SHA256, client_data.as_bytes()).as_ref());
        let signature = self.pair.sign(&signed);
        json!({
            "credential_id": base64url::encode(&self.credential_id),
            "client_data_json": base64url::encode(client_data.as_bytes()),
            "authenticator_data": base64url::encode(&data),
            "signature": base64url::encode(signature.as_ref()),
        })
    }
}
