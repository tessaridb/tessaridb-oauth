//! The companies this node serves right now: a snapshot of the directory's active companies with their issuers,
//! replaced whole by the refresh daemon and read on every request without touching the store.
//!
//! A request names its company in the path; looking that name up here costs one map read and remembers nothing, so
//! a flood of names that are not companies neither reaches the store nor grows anything.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock};

use tessari_oauth_types::TenantId;

/// Active companies and their issuers, `<base>/<company>`.
pub struct Served {
    base: String,
    issuers: RwLock<Arc<HashMap<TenantId, Arc<str>>>>,
}

impl Served {
    /// A snapshot serving nobody yet, for issuers under `base` (the public URL, no trailing slash).
    #[must_use]
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            issuers: RwLock::new(Arc::new(HashMap::new())),
        }
    }

    /// Serve exactly `active` from now on.
    pub fn replace(&self, active: impl IntoIterator<Item = TenantId>) {
        let issuers: HashMap<TenantId, Arc<str>> = active
            .into_iter()
            .map(|company| {
                let issuer: Arc<str> = format!("{}/{}", self.base, company.as_str()).into();
                (company, issuer)
            })
            .collect();
        *self.issuers.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(issuers);
    }

    /// The issuer of `company` when it is served.
    #[must_use]
    pub fn issuer(&self, company: &TenantId) -> Option<Arc<str>> {
        self.snapshot().get(company).cloned()
    }

    /// Every company served, in no particular order.
    #[must_use]
    pub fn companies(&self) -> Vec<TenantId> {
        self.snapshot().keys().cloned().collect()
    }

    /// Every company served with its issuer, in no particular order.
    #[must_use]
    pub fn issuers(&self) -> Vec<(TenantId, Arc<str>)> {
        self.snapshot()
            .iter()
            .map(|(company, issuer)| (company.clone(), Arc::clone(issuer)))
            .collect()
    }

    /// The current snapshot; the lock is held only to clone the pointer.
    fn snapshot(&self) -> Arc<HashMap<TenantId, Arc<str>>> {
        Arc::clone(&self.issuers.read().unwrap_or_else(PoisonError::into_inner))
    }
}

#[cfg(test)]
#[path = "served_tests.rs"]
mod tests;
