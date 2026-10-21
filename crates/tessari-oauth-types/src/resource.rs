//! A protected resource a token or a consent is for (RFC 8707 §2).
//!
//! The same scope at two resources is two grants, so the resource is part of what a consent covers and part of a
//! token's audience. It is compared as a string, which is only safe when one resource has one spelling: a value is
//! accepted only in the form the WHATWG parser serialises it to, `https`, with no fragment (RFC 8707 forbids one),
//! no query and no user information.

use url::Url;

use crate::{Error, Result};

/// A resource indicator as accepted from a client or a registration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Resource(String);

impl Resource {
    /// Read a resource indicator.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `resource` unless the value is an `https` URI already in normalised form,
    /// without query, fragment or user information.
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        let accepted = Url::parse(&raw).is_ok_and(|url| {
            url.as_str() == raw
                && url.scheme() == "https"
                && url.query().is_none()
                && url.fragment().is_none()
                && url.username().is_empty()
                && url.password().is_none()
        });
        if !accepted {
            return Err(Error::Invalid {
                field: "resource",
                reason: "an https URI in normalised form, without query, fragment or user information",
            });
        }
        Ok(Self(raw))
    }

    /// The resource as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[path = "resource_tests.rs"]
mod tests;
