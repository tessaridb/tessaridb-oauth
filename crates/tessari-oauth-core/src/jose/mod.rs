//! JOSE: verifying a signed object against an algorithm chosen by configuration and keys registered beforehand.
//!
//! The object never chooses how it is verified. Its `alg` header must equal the configured algorithm, its `kid`
//! only selects among keys the client registered, and keys or key locations it carries are never consulted.

mod jws;
mod key;

pub use jws::{Verified, verify, verify_embedded};
pub use key::{Algorithm, VerifyingKey};

/// Why a signed object or a key was refused. Each is answered to the caller as the same protocol error; the variant
/// is for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JoseError {
    /// Not three base64url segments, or a header that is not a JSON object of the expected shape.
    #[error("not a compact JWS")]
    Malformed,
    /// The header names an algorithm other than the configured one.
    #[error("the header's algorithm is not the configured one")]
    AlgorithmNotAllowed,
    /// The header marks extensions critical, and none is understood here.
    #[error("a critical header extension is present")]
    CriticalHeader,
    /// No registered key is selected: an unknown `kid`, or no `kid` and other than one candidate.
    #[error("no registered key matches")]
    UnknownKey,
    /// The signature does not verify under the selected key.
    #[error("the signature does not verify")]
    BadSignature,
    /// A JWK that is not a public signing key of the configured algorithm.
    #[error("the key is not a public signing key of the configured algorithm")]
    KeyRefused,
}
