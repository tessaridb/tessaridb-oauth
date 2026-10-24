use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use super::{BreachedPasswords, Unchecked, digest_hex, holds};

/// "password": its SHA-1 is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8, so the range is 5BAA6.
const PASSWORD: &str = "password";
const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

fn local_tls() -> (TlsAcceptor, RootCertStore) {
    let key = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("a certificate");
    let private = PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).expect("a key");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(vec![certificate.der().clone()], private)
    .expect("a server configuration");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate.der().to_vec()))
        .expect("a root");
    (TlsAcceptor::from(Arc::new(config)), roots)
}

/// An HTTPS service on 127.0.0.1 answering every request with `answer` after `delay`; its base URL and the requests
/// it saw.
async fn service(
    answer: String,
    delay: Duration,
) -> (String, RootCertStore, Arc<Mutex<Vec<String>>>) {
    let (acceptor, roots) = local_tls();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let base = format!(
        "https://127.0.0.1:{}/range/",
        listener.local_addr().expect("an address").port()
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let Ok(mut tls) = acceptor.accept(socket).await else {
                continue;
            };
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = tls.read(&mut buffer).await {
                request.extend_from_slice(&buffer[..read]);
                if read == 0 || String::from_utf8_lossy(&request).contains("\r\n\r\n") {
                    break;
                }
            }
            recorder
                .lock()
                .await
                .push(String::from_utf8_lossy(&request).into_owned());
            tokio::time::sleep(delay).await;
            let _ = tls.write_all(answer.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });
    (base, roots, seen)
}

fn ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn the_digest_is_upper_case_hex_sha1() {
    assert_eq!(digest_hex(PASSWORD), format!("5BAA6{SUFFIX}"));
}

#[test]
fn a_suffix_is_held_only_when_listed_with_a_count_above_zero() {
    let answer = format!("0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{SUFFIX}:42\r\n");
    assert!(holds(&answer, SUFFIX));
    assert!(holds(&answer.to_lowercase(), SUFFIX));
    assert!(!holds(&format!("{SUFFIX}:0\r\n"), SUFFIX), "a padding line");
    assert!(!holds("0018A45C4D1DEF81644B54AB7F969B88D65:3", SUFFIX));
}

#[tokio::test]
async fn only_the_range_prefix_goes_out_and_a_listed_password_is_seen() {
    let (base, roots, seen) = service(ok(&format!("{SUFFIX}:10\r\n")), Duration::ZERO).await;
    let lookups =
        BreachedPasswords::new(&base, roots, Duration::from_secs(10)).expect("a lookup service");
    assert_eq!(lookups.seen(PASSWORD).await, Ok(true));
    let requests = seen.lock().await;
    let request = requests[0].to_ascii_lowercase();
    assert!(
        request.starts_with("get /range/5baa6 http/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains("\r\nadd-padding: true\r\n"), "{request}");
    assert!(
        !request.contains(&SUFFIX.to_ascii_lowercase()),
        "the suffix stays here"
    );
    assert!(!request.contains(PASSWORD), "the password stays here");
}

#[tokio::test]
async fn a_password_missing_from_its_range_is_not_seen() {
    let (base, roots, _) = service(
        ok("0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"),
        Duration::ZERO,
    )
    .await;
    let lookups =
        BreachedPasswords::new(&base, roots, Duration::from_secs(10)).expect("a lookup service");
    assert_eq!(lookups.seen(PASSWORD).await, Ok(false));
}

#[tokio::test]
async fn a_status_other_than_200_and_a_slow_answer_are_unchecked() {
    let (base, roots, _) = service(
        "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            .to_owned(),
        Duration::ZERO,
    )
    .await;
    let lookups =
        BreachedPasswords::new(&base, roots, Duration::from_secs(10)).expect("a lookup service");
    assert_eq!(lookups.seen(PASSWORD).await, Err(Unchecked::Status(503)));
    let (base, roots, _) = service(ok(""), Duration::from_secs(5)).await;
    let lookups =
        BreachedPasswords::new(&base, roots, Duration::from_millis(200)).expect("a lookup service");
    assert_eq!(lookups.seen(PASSWORD).await, Err(Unchecked::TimedOut));
}

#[test]
fn a_base_that_is_not_https_ending_in_a_slash_is_refused() {
    for base in [
        "http://127.0.0.1/range/",
        "https://127.0.0.1/range",
        "range/",
    ] {
        assert!(
            BreachedPasswords::new(base, RootCertStore::empty(), Duration::from_secs(1)).is_err(),
            "{base}"
        );
    }
}
