use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use super::{Poster, Undelivered};

const TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzaWQiOiJzLTEifQ.c2lnbmF0dXJl";

/// A certificate for 127.0.0.1, the acceptor that serves it, and a root store that trusts it.
fn local_tls() -> (TlsAcceptor, RootCertStore) {
    let key = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("a certificate");
    let chain = vec![certificate.der().clone()];
    let private = PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).expect("a key");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(chain, private)
    .expect("a server configuration");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.der().to_vec()))
        .expect("a root");
    (TlsAcceptor::from(Arc::new(config)), roots)
}

/// What an endpoint saw: every request in full, and how many connections it accepted.
#[derive(Default)]
struct Seen {
    requests: Mutex<Vec<String>>,
    connections: AtomicUsize,
}

/// An HTTPS endpoint on 127.0.0.1 answering every request with `answer`; its URL base and what it saw.
async fn endpoint(acceptor: TlsAcceptor, answer: &'static str) -> (String, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().expect("an address").port()
    );
    let seen = Arc::new(Seen::default());
    let recorder = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            recorder.connections.fetch_add(1, Ordering::SeqCst);
            let Ok(mut tls) = acceptor.accept(socket).await else {
                continue;
            };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = tls.read(&mut buffer).await {
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request);
                if read == 0 || text.contains("\r\n\r\n") && text.ends_with(TOKEN) {
                    break;
                }
            }
            recorder
                .requests
                .lock()
                .await
                .push(String::from_utf8_lossy(&request).into_owned());
            let _ = tls.write_all(answer.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });
    (base, seen)
}

const OK: &str = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
const NO_CONTENT: &str = "HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n";
const FOUND: &str =
    "HTTP/1.1 302 Found\r\nlocation: /elsewhere\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

#[tokio::test]
async fn a_logout_token_is_posted_as_a_form_and_a_200_tells_the_client() {
    let (acceptor, roots) = local_tls();
    let (base, seen) = endpoint(acceptor, OK).await;
    let poster = Poster::new(roots, Duration::from_secs(10)).expect("a poster");
    poster
        .deliver(&format!("{base}/backchannel?tenant=acme"), TOKEN)
        .await
        .expect("told");
    let requests = seen.requests.lock().await;
    assert_eq!(requests.len(), 1);
    let request = requests[0].to_ascii_lowercase();
    assert!(
        request.starts_with("post /backchannel?tenant=acme http/1.1\r\n"),
        "{request}"
    );
    assert!(
        request.contains("\r\ncontent-type: application/x-www-form-urlencoded\r\n"),
        "{request}"
    );
    assert!(request.contains("\r\nhost: 127.0.0.1:"), "{request}");
    assert!(
        requests[0].ends_with(&format!("\r\n\r\nlogout_token={TOKEN}")),
        "{}",
        requests[0]
    );
}

#[tokio::test]
async fn a_204_tells_the_client_too() {
    let (acceptor, roots) = local_tls();
    let (base, _) = endpoint(acceptor, NO_CONTENT).await;
    let poster = Poster::new(roots, Duration::from_secs(10)).expect("a poster");
    poster
        .deliver(&format!("{base}/bc"), TOKEN)
        .await
        .expect("told");
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let (acceptor, roots) = local_tls();
    let (base, seen) = endpoint(acceptor, FOUND).await;
    let poster = Poster::new(roots, Duration::from_secs(10)).expect("a poster");
    let refused = poster.deliver(&format!("{base}/bc"), TOKEN).await;
    assert_eq!(refused, Err(Undelivered::Status(302)));
    assert_eq!(
        seen.connections.load(Ordering::SeqCst),
        1,
        "one request, nothing followed"
    );
}

#[tokio::test]
async fn an_endpoint_that_is_not_https_is_never_called() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let poster = Poster::new(RootCertStore::empty(), Duration::from_secs(10)).expect("a poster");
    let refused = poster
        .deliver(&format!("http://127.0.0.1:{port}/bc"), TOKEN)
        .await;
    assert_eq!(refused, Err(Undelivered::NotHttpsUrl));
    let accepted = tokio::time::timeout(Duration::from_millis(1), listener.accept()).await;
    assert!(accepted.is_err(), "no connection was made");
}

#[tokio::test]
async fn link_local_addresses_such_as_cloud_metadata_are_never_called() {
    let poster = Poster::new(RootCertStore::empty(), Duration::from_secs(10)).expect("a poster");
    for uri in [
        "https://169.254.169.254/latest/meta-data",
        "https://[fe80::1]/bc",
        "https://[::ffff:169.254.169.254]/bc",
        "https://0.0.0.0/bc",
        "https://224.0.0.1/bc",
    ] {
        assert_eq!(
            poster.deliver(uri, TOKEN).await,
            Err(Undelivered::ForbiddenAddress),
            "{uri}"
        );
    }
}

#[tokio::test]
async fn an_endpoint_whose_certificate_is_not_trusted_is_not_told() {
    let (acceptor, _) = local_tls();
    let (_, other_roots) = local_tls();
    let (base, seen) = endpoint(acceptor, OK).await;
    let poster = Poster::new(other_roots, Duration::from_secs(10)).expect("a poster");
    assert_eq!(
        poster.deliver(&format!("{base}/bc"), TOKEN).await,
        Err(Undelivered::Tls)
    );
    assert!(seen.requests.lock().await.is_empty(), "no token was sent");
}

#[tokio::test(start_paused = true)]
async fn an_endpoint_that_never_answers_is_given_up_on() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    // Accepts and then says nothing at all, not even its half of the handshake.
    let held = tokio::spawn(async move {
        let mut sockets = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            sockets.push(socket);
        }
    });
    let poster = Poster::new(RootCertStore::empty(), Duration::from_secs(5)).expect("a poster");
    let refused = tokio::time::timeout(
        Duration::from_secs(60),
        poster.deliver(&format!("https://127.0.0.1:{port}/bc"), TOKEN),
    )
    .await
    .expect("the poster gave up on its own");
    assert_eq!(refused, Err(Undelivered::TimedOut));
    held.abort();
}
