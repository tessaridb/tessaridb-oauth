//! A registered redirect URI and the one comparison it permits (RFC 9700 §4.1.3, RFC 8252 §7.3).
//!
//! The authorization code is delivered to this URI, so a match that is anything looser than exact sends codes to
//! whoever controls the looser part: a prefix lets an attacker extend the path, a host wildcard admits a sibling
//! deployment, a tolerated query or trailing slash is a second URI nobody registered. The comparison is therefore
//! string equality against the registered value, and the server never normalises an incoming value into a match.
//!
//! # The one exception
//!
//! A native application listens on a loopback port the operating system assigns at run time, so it cannot
//! register the port. For a registered `http` URI on a loopback IP literal (`127.0.0.1` or `[::1]`) the port of
//! the presented URI may vary; scheme, host, path and query still match exactly. `localhost` is not a loopback
//! literal — the name can resolve elsewhere — and `http` is refused for every other host.
//!
//! # Strict parse
//!
//! A registered value must already be in the form the WHATWG URL parser serialises it to. A value that only
//! matches after normalisation (an upper-case host, an explicit default port, a missing root slash) is refused at
//! registration, because the alternative is a server that normalises presented values too — and normalisation is
//! where two different strings start comparing equal.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::{Error, Result};

const FIELD: &str = "redirect_uri";

/// A redirect URI as registered for a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectUri {
    raw: String,
    /// For a loopback URI, the registered value with its port removed: the form a presented URI is compared in.
    loopback_without_port: Option<String>,
}

/// Parse `raw` and keep it only when it is already in normalised form and carries no fragment or user information.
fn strict(raw: &str) -> Option<Url> {
    let url = Url::parse(raw).ok()?;
    let clean = url.as_str() == raw
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    clean.then_some(url)
}

/// Whether `url` is `http` on a loopback IP literal — the only place `http` is permitted (RFC 8252 §7.3).
fn is_loopback(url: &Url) -> bool {
    url.scheme() == "http"
        && matches!(
            url.host(),
            Some(Host::Ipv4(Ipv4Addr::LOCALHOST)) | Some(Host::Ipv6(Ipv6Addr::LOCALHOST))
        )
}

/// The serialised form of `url` with its port removed.
fn without_port(mut url: Url) -> Option<String> {
    url.set_port(None).ok()?;
    Some(url.into())
}

impl RedirectUri {
    /// Read a redirect URI for registration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `redirect_uri` when the value is not an absolute URI in normalised form, has
    /// a fragment or user information, uses `http` on anything other than a loopback IP literal, or uses a scheme
    /// that is neither `https`, `http` nor a private-use scheme containing a period (RFC 8252 §7.1).
    pub fn parse(raw: impl Into<String>) -> Result<Self> {
        let raw = raw.into();
        let Some(url) = strict(&raw) else {
            return Err(Error::Invalid {
                field: FIELD,
                reason: "an absolute URI in normalised form, without fragment or user information",
            });
        };
        let loopback_without_port = match url.scheme() {
            "https" => None,
            "http" if is_loopback(&url) => without_port(url),
            "http" => {
                return Err(Error::Invalid {
                    field: FIELD,
                    reason: "http is permitted only on 127.0.0.1 or [::1]",
                });
            }
            scheme if scheme.contains('.') => None,
            _ => {
                return Err(Error::Invalid {
                    field: FIELD,
                    reason: "the scheme is neither https nor a private-use scheme with a period",
                });
            }
        };
        Ok(Self {
            raw,
            loopback_without_port,
        })
    }

    /// Whether `presented` is this registered URI, as the authorization and token requests must name it.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        if presented == self.raw {
            return true;
        }
        let Some(registered) = &self.loopback_without_port else {
            return false;
        };
        // Equality with the registered port-free form already pins scheme `http` and the loopback host, so only
        // the port can differ.
        strict(presented)
            .and_then(without_port)
            .is_some_and(|presented| presented == *registered)
    }

    /// The URI as registered.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
#[path = "redirect_uri_tests.rs"]
mod tests;
