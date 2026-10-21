//! What the public routes read: the tenants this server is the issuer for, their key records, and the clock.

use std::collections::HashMap;
use std::sync::Arc;

use tessari_oauth_storage::keys::KeyService;
use tessari_oauth_types::{Clock, TenantId};

use crate::{Error, Result};

/// The state the public router serves from. Everything in it is shared read-only, so no lock is ever taken.
#[derive(Clone)]
pub struct PublicState {
    /// The tenants' signing-key records.
    pub keys: Arc<KeyService>,
    /// Each served tenant's issuer identifier, fixed at start-up from the configuration.
    pub issuers: Arc<HashMap<TenantId, String>>,
    /// The clock the key rule is judged at.
    pub clock: Clock,
}

impl PublicState {
    /// The served tenant the path segment `raw` names, with its issuer.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] for a segment that is not a tenant id or names a tenant this server does not serve — one
    /// answer for both, so the path is not an oracle for which tenants exist.
    pub(crate) fn tenant(&self, raw: &str) -> Result<(TenantId, &str)> {
        let tenant = TenantId::parse(raw).map_err(|_| Error::NotFound)?;
        let issuer = self.issuers.get(&tenant).ok_or(Error::NotFound)?;
        Ok((tenant, issuer.as_str()))
    }
}
