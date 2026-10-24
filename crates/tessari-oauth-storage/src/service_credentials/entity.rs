//! `services` rows exactly as stored.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// One registered service; its record id is its service id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntity {
    /// The service id.
    pub service_id: String,
    /// The Ed25519 public key, as a JWK.
    pub public_jwk: String,
    /// The operator roles it may act with, by name.
    pub roles: Vec<String>,
    /// Who registered it.
    pub registered_by: String,
    /// When, in Unix seconds.
    pub registered_at: i64,
    /// Why.
    pub reason: String,
}

impl FromRecord for ServiceEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            service_id: row.take("service_id")?,
            public_jwk: row.take("public_jwk")?,
            roles: row.take("roles")?,
            registered_by: row.take("registered_by")?,
            registered_at: row.take("registered_at")?,
            reason: row.take("reason")?,
        })
    }
}
