//! The companies other regions serve, with the public base URL of the region each lives in: a snapshot of the peer
//! regions' directories, replaced whole by the peer refresh daemon and read on a request for a company this node
//! does not serve, so that request can be sent to the company's home rather than refused.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use tessari_oauth_types::TenantId;

/// Companies served by other regions, by the base URL of their home.
pub struct Elsewhere {
    homes: RwLock<Arc<HashMap<TenantId, Arc<str>>>>,
}

impl Default for Elsewhere {
    fn default() -> Self {
        Self::new()
    }
}

impl Elsewhere {
    /// A snapshot naming no company.
    #[must_use]
    pub fn new() -> Self {
        Self {
            homes: RwLock::new(Arc::new(HashMap::new())),
        }
    }

    /// Know exactly `homes` from now on: each company with the base URL of the region serving it.
    pub fn replace(&self, homes: impl IntoIterator<Item = (TenantId, Arc<str>)>) {
        let homes: HashMap<TenantId, Arc<str>> = homes.into_iter().collect();
        *self.homes.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(homes);
    }

    /// The base URL of the region serving `company`, when another region does.
    #[must_use]
    pub fn home(&self, company: &TenantId) -> Option<Arc<str>> {
        // The lock is held only to clone the pointer.
        let homes = Arc::clone(&self.homes.read().unwrap_or_else(PoisonError::into_inner));
        homes.get(company).cloned()
    }
}

#[cfg(test)]
#[path = "elsewhere_tests.rs"]
mod tests;
