//! Looking a new password up among passwords seen in breaches (NIST SP 800-63B-4 §3.1.1.2) without sending it: a
//! range query sends the first five hex digits of its SHA-1 and reads back the suffixes of every digest sharing them,
//! each with how often it was seen, and the match happens here. The request asks for padding, so the answer's size
//! does not tell an observer which range was asked about.
//!
//! The lookup is outbound HTTPS to a place the operator configured: the same vetting as a back-channel delivery
//! applies, a redirect is never followed, and the whole exchange has one deadline. Neither the password nor its digest
//! appears in an error or a log line.

use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::{Either, select};
use hyper::body::Body;
use hyper::header::HOST;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use rustls::{ClientConfig, RootCertStore};
use tessari_oauth_constants::{
    BREACHED_PASSWORDS_MAX_ANSWER_BYTES, BREACHED_PASSWORDS_PREFIX_DIGITS,
};
use tokio_rustls::TlsConnector;
use url::{Position, Url};

use crate::backchannel::{connected, vetted};
use crate::{Error, Result};

/// Why a lookup did not answer; the password is then judged without the list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unchecked {
    /// The service could not be reached, its name resolved to no address this server calls, or TLS failed.
    #[error("the breached-password service could not be reached")]
    Unreachable,
    /// The service answered with a status other than `200`, a redirect included.
    #[error("the breached-password service answered {0}")]
    Status(u16),
    /// The answer was larger than any range answer, or not text.
    #[error("the breached-password service answered something other than a range")]
    Unreadable,
    /// The service did not answer within the deadline.
    #[error("the breached-password service did not answer in time")]
    TimedOut,
}

/// Looks passwords up among those seen in breaches, at one `https` base URL, each lookup under one deadline.
pub struct BreachedPasswords {
    connector: TlsConnector,
    base: Url,
    timeout: Duration,
}

impl BreachedPasswords {
    /// Lookups at `base` (the range prefix is appended to it), trusting `roots`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming `breached_passwords_url` when `base` is not an `https` URL ending in `/`, or
    /// no protocol version is available on the provider.
    pub fn new(base: &str, roots: RootCertStore, timeout: Duration) -> Result<Self> {
        let invalid = |reason| Error::InvalidConfig {
            field: "breached_passwords_url",
            reason,
        };
        let base = Url::parse(base).map_err(|_| invalid("not a URL"))?;
        if base.scheme() != "https" || base.host().is_none() || !base.path().ends_with('/') {
            return Err(invalid("not an https URL ending in /"));
        }
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| invalid("no protocol version is available"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            base,
            timeout,
        })
    }

    /// Lookups at `base`, trusting the operating system's certificate store.
    ///
    /// # Errors
    ///
    /// As [`BreachedPasswords::new`], and when the store yields no usable certificate.
    pub fn with_native_roots(base: &str, timeout: Duration) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        let (added, _) =
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        if added == 0 {
            return Err(Error::InvalidConfig {
                field: "breached_passwords_url",
                reason: "the system certificate store holds no usable certificate",
            });
        }
        Self::new(base, roots, timeout)
    }

    /// Whether `password` was seen in a breach.
    ///
    /// # Errors
    ///
    /// The [`Unchecked`] reason when the service did not answer.
    pub async fn seen(&self, password: &str) -> std::result::Result<bool, Unchecked> {
        let hex = digest_hex(password);
        let (prefix, suffix) = hex.split_at(BREACHED_PASSWORDS_PREFIX_DIGITS);
        let answer = tokio::time::timeout(self.timeout, self.range(prefix))
            .await
            .unwrap_or(Err(Unchecked::TimedOut))?;
        Ok(holds(&answer, suffix))
    }

    async fn range(&self, prefix: &str) -> std::result::Result<String, Unchecked> {
        let url = self.base.join(prefix).map_err(|_| Unchecked::Unreachable)?;
        let port = url.port_or_known_default().ok_or(Unchecked::Unreachable)?;
        let (addresses, name) = vetted(&url, port)
            .await
            .map_err(|_| Unchecked::Unreachable)?;
        let request = Request::get(&url[Position::BeforePath..Position::AfterQuery])
            .header(HOST, &url[Position::BeforeHost..Position::AfterPort])
            .header("Add-Padding", "true")
            .body(String::new())
            .map_err(|_| Unchecked::Unreachable)?;
        let socket = connected(&addresses)
            .await
            .map_err(|_| Unchecked::Unreachable)?;
        let tls = self
            .connector
            .connect(name, socket)
            .await
            .map_err(|_| Unchecked::Unreachable)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| Unchecked::Unreachable)?;
        let answered = pin!(async move {
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| Unchecked::Unreachable)?;
            if response.status() != StatusCode::OK {
                return Err(Unchecked::Status(response.status().as_u16()));
            }
            read_body(response.into_body()).await
        });
        match select(answered, pin!(connection)).await {
            Either::Left((answer, _)) => answer,
            Either::Right((_, answered)) => answered.await,
        }
    }
}

/// The body of an answer, refused past the size of any range answer.
async fn read_body(mut body: hyper::body::Incoming) -> std::result::Result<String, Unchecked> {
    let mut bytes = Vec::new();
    while let Some(frame) =
        std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
    {
        let frame = frame.map_err(|_| Unchecked::Unreachable)?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > BREACHED_PASSWORDS_MAX_ANSWER_BYTES {
                return Err(Unchecked::Unreadable);
            }
            bytes.extend_from_slice(&data);
        }
    }
    String::from_utf8(bytes).map_err(|_| Unchecked::Unreadable)
}

/// The SHA-1 of `password` in upper-case hex, the form a range answer lists.
fn digest_hex(password: &str) -> String {
    digest(&SHA1_FOR_LEGACY_USE_ONLY, password.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect()
}

/// Whether a range `answer` (lines of `SUFFIX:COUNT`) lists `suffix` as seen at least once; a padding line counts 0.
fn holds(answer: &str, suffix: &str) -> bool {
    answer.lines().any(|line| {
        line.trim().split_once(':').is_some_and(|(listed, count)| {
            listed.eq_ignore_ascii_case(suffix)
                && count.trim().parse::<u64>().is_ok_and(|count| count > 0)
        })
    })
}

#[cfg(test)]
#[path = "breached_tests.rs"]
mod tests;
