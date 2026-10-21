//! The tenant a request is for — the issuer's path segment, `https://<host>/<tenant>`.
//!
//! A tenant is an issuer with its own keys, clients, users and consents, so every check that compares `iss`
//! compares against the tenant the request is FOR. A type rather than a string so that a tenant id cannot be passed
//! where a client id or a subject was meant.

use tessari_oauth_constants::TENANT_ID_MAX_LEN;

use crate::{Error, Result};

/// A tenant's id: 1 to 63 lowercase letters, digits and inner hyphens.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(String);

impl TenantId {
    /// Read a tenant id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `tenant` when the value is empty, longer than 63 bytes, holds anything but
    /// lowercase ASCII letters, digits and hyphens, or starts or ends with a hyphen. One spelling per tenant, so
    /// two issuers can never differ only in case.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        let bytes = raw.as_bytes();
        let within_length = (1..=TENANT_ID_MAX_LEN).contains(&bytes.len());
        let alphabet = bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
        let inner_hyphens = bytes.first() != Some(&b'-') && bytes.last() != Some(&b'-');
        if !(within_length && alphabet && inner_hyphens) {
            return Err(Error::Invalid {
                field: "tenant",
                reason: "1 to 63 lowercase letters, digits and inner hyphens",
            });
        }
        Ok(Self(raw))
    }

    /// The id as written in the issuer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "tenant_id_tests.rs"]
mod tests;
