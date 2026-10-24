//! Service credentials as the rest of the server uses them.

use tessari_oauth_core::jose::VerifyingKey;
use tessari_oauth_types::{ServiceId, Timestamp};

use crate::operators::OperatorRole;

/// A service to register.
#[derive(Debug, Clone)]
pub struct NewService {
    /// Its id.
    pub id: ServiceId,
    /// Its Ed25519 public key, as a JWK.
    pub public_jwk: String,
    /// The roles it may act with.
    pub roles: Vec<OperatorRole>,
    /// Who registers it.
    pub registered_by: String,
    /// Why.
    pub reason: String,
}

/// A registered service.
#[derive(Debug, Clone)]
pub struct ServiceCredential {
    /// Its id.
    pub id: ServiceId,
    /// The key its assertions verify under.
    pub key: VerifyingKey,
    /// The roles it may act with.
    pub roles: Vec<OperatorRole>,
    /// Who registered it.
    pub registered_by: String,
    /// When.
    pub registered_at: Timestamp,
}
