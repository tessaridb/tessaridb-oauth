//! The signature algorithms this server signs and verifies with (RFC 7518 §3.4, RFC 8037). Only elliptic curves:
//! small signatures and no padding history. A type shared by the verifier and the key custody, so both name an
//! algorithm the same way and neither can accept one the other does not know.

/// A signature algorithm this server accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[cfg(test)]
#[path = "algorithm_tests.rs"]
mod tests;
