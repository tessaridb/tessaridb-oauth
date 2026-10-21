//! Where a tenant's records live: one namespace per region, one database per tenant inside it.
//!
//! A tenant's identity data stays in its home region, so the region is the namespace and the tenant the database.
//! Tenant ids hold lowercase letters, digits and hyphens and never an underscore, so mapping `-` to `_` is
//! one-to-one: two tenants can never share a database name.

use tessari_oauth_infrastructure::tessaridb::Place;
use tessari_oauth_types::TenantId;

use crate::Result;

/// The region this server's storage belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenancy {
    namespace: String,
}

impl Tenancy {
    /// The tenancy of `region`, whose namespace is `oauth_<region>`.
    ///
    /// # Errors
    ///
    /// When `oauth_<region>` is not a plain name.
    pub fn for_region(region: &str) -> Result<Self> {
        let namespace = format!("oauth_{region}");
        Place::new(namespace.as_str(), "probe")?;
        Ok(Self { namespace })
    }

    /// Where `tenant`'s records live.
    ///
    /// # Errors
    ///
    /// Never for a valid tenant id; the check stays because the name becomes statement text.
    pub fn place(&self, tenant: &TenantId) -> Result<Place> {
        let database = format!("t_{}", tenant.as_str().replace('-', "_"));
        Ok(Place::new(self.namespace.as_str(), database)?)
    }
}

#[cfg(test)]
#[path = "tenancy_tests.rs"]
mod tests;
