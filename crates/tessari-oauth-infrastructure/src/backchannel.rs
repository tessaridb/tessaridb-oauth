//! Back-channel delivery (OpenID Connect Back-Channel Logout 1.0 §2.5): one HTTPS `POST` of a logout token to the
//! endpoint a client registered, answered `200` or `204` when the client was told.
//!
//! The endpoint is a URL somebody typed into a client registration, so this is outbound traffic toward a destination
//! the server did not choose. Only `https` is spoken, every address the host resolves to is vetted and the connection
//! goes to a vetted one (never a second lookup). Unspecified, multicast, broadcast and link-local addresses are never
//! called; cloud metadata services live in the link-local range. A redirect is never followed, and the whole exchange
//! has one deadline. Loopback and private addresses are called: a relying party's back-channel endpoint normally sits
//! inside the operator's own network. The token appears in the request body only, never in an error or a log line.

use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::{Either, select};
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::{Host, Position, Url};

use crate::{Error, Result};

/// Why a logout token did not reach its client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Undelivered {
    /// The registered endpoint is not an `https` URL with a host.
    #[error("the endpoint is not an https URL with a host")]
    NotHttpsUrl,
    /// The endpoint's host resolves to no address this server calls.
    #[error("the endpoint resolves to no address this server calls")]
    ForbiddenAddress,
    /// The endpoint could not be reached.
    #[error("the endpoint could not be reached: {0}")]
    Unreachable(std::io::ErrorKind),
    /// TLS with the endpoint failed: an untrusted certificate, a wrong name, or no common protocol.
    #[error("TLS with the endpoint failed")]
    Tls,
    /// The connection broke before an answer arrived.
    #[error("the endpoint broke off the exchange")]
    BrokenOff,
    /// The endpoint answered with a status that does not tell, a redirect included.
    #[error("the endpoint answered {0}")]
    Status(u16),
    /// The endpoint did not answer within the poster's deadline.
    #[error("the endpoint did not answer in time")]
    TimedOut,
}

/// Posts logout tokens over HTTPS, trusting one set of roots, each exchange under one deadline.
pub struct Poster {
    connector: TlsConnector,
    timeout: Duration,
}

/// Whether `address` is one this server never calls.
fn never_called(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() || v4.is_link_local()
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => never_called(IpAddr::V4(v4)),
            None => v6.is_unspecified() || v6.is_multicast() || v6.is_unicast_link_local(),
        },
    }
}

impl Poster {
    /// A poster trusting `roots`, giving each exchange `timeout` from lookup to answer.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming `backchannel_roots` when no protocol version is available on the provider.
    pub fn new(roots: RootCertStore, timeout: Duration) -> Result<Self> {
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| Error::InvalidConfig {
                    field: "backchannel_roots",
                    reason: "no protocol version is available",
                })?
                .with_root_certificates(roots)
                .with_no_client_auth();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            timeout,
        })
    }

    /// A poster trusting the operating system's certificate store.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming `backchannel_roots` when the store yields no usable certificate.
    pub fn with_native_roots(timeout: Duration) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        let (added, _) =
            roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        if added == 0 {
            return Err(Error::InvalidConfig {
                field: "backchannel_roots",
                reason: "the system certificate store holds no usable certificate",
            });
        }
        Self::new(roots, timeout)
    }

    /// Post `logout_token` to `uri`; `Ok` when the client answered `200` or `204`.
    ///
    /// # Errors
    ///
    /// The [`Undelivered`] reason; nothing is retried here.
    pub async fn deliver(
        &self,
        uri: &str,
        logout_token: &str,
    ) -> std::result::Result<(), Undelivered> {
        tokio::time::timeout(self.timeout, self.exchange(uri, logout_token))
            .await
            .unwrap_or(Err(Undelivered::TimedOut))
    }

    async fn exchange(
        &self,
        uri: &str,
        logout_token: &str,
    ) -> std::result::Result<(), Undelivered> {
        let url = Url::parse(uri).map_err(|_| Undelivered::NotHttpsUrl)?;
        if url.scheme() != "https" {
            return Err(Undelivered::NotHttpsUrl);
        }
        let port = url
            .port_or_known_default()
            .ok_or(Undelivered::NotHttpsUrl)?;
        let (address, name) = vetted(&url, port).await?;
        let request = Request::post(&url[Position::BeforePath..Position::AfterQuery])
            .header(HOST, &url[Position::BeforeHost..Position::AfterPort])
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("logout_token", logout_token)
                    .finish(),
            )
            .map_err(|_| Undelivered::NotHttpsUrl)?;
        let socket = TcpStream::connect(address)
            .await
            .map_err(|failure| Undelivered::Unreachable(failure.kind()))?;
        let tls = self
            .connector
            .connect(name, socket)
            .await
            .map_err(|_| Undelivered::Tls)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| Undelivered::BrokenOff)?;
        // The answer's status is all that is read; the response, and with it its body, is dropped at once.
        let answered = pin!(async move {
            sender
                .send_request(request)
                .await
                .map(|response| response.status())
        });
        let status = match select(answered, pin!(connection)).await {
            Either::Left((status, _)) => status,
            Either::Right((_, answered)) => answered.await,
        }
        .map_err(|_| Undelivered::BrokenOff)?;
        match status {
            StatusCode::OK | StatusCode::NO_CONTENT => Ok(()),
            other => Err(Undelivered::Status(other.as_u16())),
        }
    }
}

/// The address to connect to for `url` and the name its certificate must carry.
async fn vetted(
    url: &Url,
    port: u16,
) -> std::result::Result<(SocketAddr, ServerName<'static>), Undelivered> {
    let (candidates, name): (Vec<SocketAddr>, ServerName<'static>) = match url.host() {
        Some(Host::Ipv4(v4)) => (
            vec![SocketAddr::new(IpAddr::V4(v4), port)],
            ServerName::IpAddress(IpAddr::V4(v4).into()),
        ),
        Some(Host::Ipv6(v6)) => (
            vec![SocketAddr::new(IpAddr::V6(v6), port)],
            ServerName::IpAddress(IpAddr::V6(v6).into()),
        ),
        Some(Host::Domain(domain)) => (
            tokio::net::lookup_host((domain, port))
                .await
                .map_err(|_| Undelivered::ForbiddenAddress)?
                .collect(),
            ServerName::try_from(domain.to_owned()).map_err(|_| Undelivered::NotHttpsUrl)?,
        ),
        None => return Err(Undelivered::NotHttpsUrl),
    };
    let address = candidates
        .into_iter()
        .find(|candidate| !never_called(candidate.ip()))
        .ok_or(Undelivered::ForbiddenAddress)?;
    Ok((address, name))
}

#[cfg(test)]
#[path = "backchannel_tests.rs"]
mod tests;
