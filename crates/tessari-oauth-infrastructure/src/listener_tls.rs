//! The TLS a listener serves with: a certificate chain and its private key, read from PEM once at startup.

use std::fmt;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{Error, Result};

/// A listener's certificate chain and private key, as PEM. The key never appears in debug output.
pub struct ListenerTls {
    certificate_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

impl ListenerTls {
    /// The material as read.
    #[must_use]
    pub const fn new(certificate_pem: Vec<u8>, key_pem: Vec<u8>) -> Self {
        Self {
            certificate_pem,
            key_pem,
        }
    }
}

impl fmt::Debug for ListenerTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListenerTls")
            .field("certificate_pem", &self.certificate_pem.len())
            .finish_non_exhaustive()
    }
}

const fn invalid(field: &'static str, reason: &'static str) -> Error {
    Error::InvalidConfig { field, reason }
}

/// The server configuration for `tls`: TLS 1.2 and 1.3 on the ring provider, no client certificates.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming `tls_certificate` when the chain is not PEM certificates or is empty, and
/// `tls_key` when the key is not a PEM private key or does not belong to the certificate.
pub fn listener_config(tls: &ListenerTls) -> Result<Arc<ServerConfig>> {
    let chain = CertificateDer::pem_slice_iter(&tls.certificate_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| invalid("tls_certificate", "not PEM certificates"))?;
    if chain.is_empty() {
        return Err(invalid("tls_certificate", "holds no certificate"));
    }
    let key = PrivateKeyDer::from_pem_slice(&tls.key_pem)
        .map_err(|_| invalid("tls_key", "not a PEM private key"))?;
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| invalid("tls_certificate", "no protocol version both sides speak"))?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|_| invalid("tls_key", "does not belong to the certificate"))?;
    Ok(Arc::new(config))
}

#[cfg(test)]
#[path = "listener_tls_tests.rs"]
mod tests;
