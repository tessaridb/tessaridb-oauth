//! Where a tenant's records live: one namespace per region, one database per tenant inside it.
//!
//! A tenant's identity data stays in its home region, so the region is the namespace and the tenant the database.
//! Tenant ids hold lowercase letters, digits and hyphens and never an underscore, so mapping `-` to `_` is
//! one-to-one: two tenants can never share a database name. The region's request counters live beside them in a
//! database named `throttle`, and its directory of companies in one named `directory`; no tenant's `t_` name can be
//! either.

use tessari_oauth_infrastructure::tessaridb::Place;
use tessari_oauth_types::TenantId;

use crate::Result;

/// The region this server's storage belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenancy {
    namespace: String,
    throttle: Place,
    directory: Place,
}

impl Tenancy {
    /// The tenancy of `region`, whose namespace is `oauth_<region>`.
    ///
    /// # Errors
    ///
    /// When `oauth_<region>` is not a plain name.
    pub fn for_region(region: &str) -> Result<Self> {
        let namespace = format!("oauth_{region}");
        let throttle = Place::new(namespace.as_str(), "throttle")?;
        let directory = Place::new(namespace.as_str(), "directory")?;
        Ok(Self {
            namespace,
            throttle,
            directory,
        })
    }

    /// Where the region's request counters live; built once, because every counted request needs it.
    pub(crate) const fn throttle(&self) -> &Place {
        &self.throttle
    }

    /// Where the region's directory of companies lives.
    pub(crate) const fn directory(&self) -> &Place {
        &self.directory
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
