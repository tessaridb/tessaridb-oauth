//! A signing key as the services hand it over.

use tessari_oauth_types::{Algorithm, KeyThumbprint, Timestamp};

/// One signing key of a tenant. `sealed` is opaque here: only key custody can open it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKey {
    /// The key's id, its RFC 7638 thumbprint.
    pub kid: KeyThumbprint,
    /// The algorithm it signs with.
    pub algorithm: Algorithm,
    /// The private half, sealed for this tenant and `kid`.
    pub sealed: Vec<u8>,
    /// The public half as the key set publishes it.
    pub public_jwk: String,
    /// When it was made, which is when it was published.
    pub created_at: Timestamp,
    /// Whether it has been withdrawn.
    pub compromised: bool,
}
