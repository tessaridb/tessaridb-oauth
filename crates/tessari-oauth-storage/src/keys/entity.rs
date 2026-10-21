//! A `signing_keys` row exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One signing key's row; its record id is the key's thumbprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntity {
    /// The key's thumbprint, also its record id.
    pub kid: String,
    /// The tenant the key signs for.
    pub tenant: String,
    /// `EdDSA` or `ES256`.
    pub algorithm: String,
    /// The sealed private half, base64url.
    pub sealed: String,
    /// The public JWK.
    pub public_jwk: String,
    /// Unix seconds of its making.
    pub created_at: i64,
    /// Whether it was withdrawn.
    pub compromised: bool,
    /// Unix seconds of its retirement; absent while it is live.
    pub retired_at: Option<i64>,
}

impl FromRecord for KeyEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            kid: row.take("kid")?,
            tenant: row.take("tenant")?,
            algorithm: row.take("algorithm")?,
            sealed: row.take("sealed")?,
            public_jwk: row.take("public_jwk")?,
            created_at: row.take("created_at")?,
            compromised: row.take("compromised")?,
            retired_at: row.take("retired_at")?,
        })
    }
}
