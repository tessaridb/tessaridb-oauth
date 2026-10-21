use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::routing::{get, put};
use rustls::pki_types::{CertificateDer, ServerName};
use tessari_oauth_infrastructure::{ListenerTls, listener_config};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use super::{Patience, serve_with};

const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

const QUICK: Patience = Patience {
    headers: Duration::from_millis(300),
    handshake: Duration::from_millis(300),
    body_idle: Duration::from_millis(300),
    connections: 2,
};

fn echo() -> axum::Router {
    axum::Router::new().route("/", get(|| async { "served" }))
}

/// A router whose `PUT /` answers how many body bytes arrived, or `stalled` when the body failed.
fn reader() -> axum::Router {
    axum::Router::new().route(
        "/",
        put(|body: Body| async move {
            match axum::body::to_bytes(body, 1024).await {
                Ok(bytes) => format!("read {}", bytes.len()),
                Err(_) => "stalled".to_owned(),
            }
        }),
    )
}

/// A self-signed `localhost` certificate: the listener's TLS and the certificate a client must trust.
fn localhost_tls() -> (Arc<rustls::ServerConfig>, CertificateDer<'static>) {
    let key = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("a certificate");
    let tls = ListenerTls::new(
        certificate.pem().into_bytes(),
        key.serialize_pem().into_bytes(),
    );
    (
        listener_config(&tls).expect("listener TLS"),
        certificate.der().clone(),
    )
}

/// `router` served under [`QUICK`] on a free port, over `tls` when given, until the returned sender fires or drops.
async fn quick(
    router: axum::Router,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> (String, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
    let address = listener.local_addr().expect("bound").to_string();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let shutdown = async move {
            let _ = stopped.await;
        };
        serve_with(listener, router, tls, shutdown, "test", &QUICK)
            .await
            .expect("serves");
    });
    (address, stop, server)
}

async fn answer(stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin)) -> String {
    stream.write_all(REQUEST).await.expect("request sent");
    let mut bytes = Vec::new();
    let _read = stream.read_to_end(&mut bytes).await;
    String::from_utf8_lossy(&bytes).into_owned()
}

/// What the server sends before it closes, or `None` when it still holds the connection after `within`.
async fn closed_within(stream: &mut TcpStream, within: Duration) -> Option<String> {
    let mut bytes = Vec::new();
    match tokio::time::timeout(within, stream.read_to_end(&mut bytes)).await {
        Ok(_) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(_) => None,
    }
}

#[tokio::test]
async fn a_request_over_tls_is_served_after_the_handshake() {
    let (config, trusted) = localhost_tls();
    let (address, _stop, _server) = quick(echo(), Some(config)).await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trusted).expect("trusted");
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(&address).await.expect("connects");
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("the handshake completes");
    let served = answer(&mut tls).await;
    assert!(served.ends_with("served"), "{served}");
}

#[tokio::test]
async fn a_client_that_never_finishes_its_handshake_is_cut_and_frees_its_slot() {
    let (config, _) = localhost_tls();
    let (address, _stop, _server) = quick(echo(), Some(config)).await;
    let mut silent = Vec::new();
    for _ in 0..2 {
        silent.push(TcpStream::connect(&address).await.expect("connects"));
    }
    for stream in &mut silent {
        let seen = closed_within(stream, Duration::from_secs(3)).await;
        assert!(seen.is_some(), "a silent TLS client is still held");
    }
    // Both slots were taken by silent clients and are free again: a plain TCP peer is accepted and cut in turn.
    let mut next = TcpStream::connect(&address).await.expect("connects");
    assert!(
        closed_within(&mut next, Duration::from_secs(3))
            .await
            .is_some()
    );
}

#[tokio::test]
async fn a_client_that_trickles_its_headers_is_closed() {
    let (address, _stop, _server) = quick(echo(), None).await;
    let mut stream = TcpStream::connect(&address).await.expect("connects");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: local")
        .await
        .expect("half the headers");
    let seen = closed_within(&mut stream, Duration::from_secs(3)).await;
    assert!(seen.is_some(), "the connection is still held");
    assert!(
        !seen.unwrap_or_default().contains("served"),
        "no request was served"
    );
}

#[tokio::test]
async fn a_body_that_stops_arriving_fails_the_request() {
    let (address, _stop, _server) = quick(reader(), None).await;
    let mut stream = TcpStream::connect(&address).await.expect("connects");
    stream
        .write_all(
            b"PUT / HTTP/1.1\r\nHost: local\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc",
        )
        .await
        .expect("headers and a part of the body");
    let seen = closed_within(&mut stream, Duration::from_secs(3)).await;
    assert!(
        seen.as_deref()
            .is_some_and(|answer| answer.ends_with("stalled")),
        "{seen:?}"
    );
}

#[tokio::test]
async fn a_slow_but_steady_body_is_read_whole() {
    let (address, _stop, _server) = quick(reader(), None).await;
    let mut stream = TcpStream::connect(&address).await.expect("connects");
    stream
        .write_all(
            b"PUT / HTTP/1.1\r\nHost: local\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("headers");
    for piece in [b"a", b"b", b"c", b"d"] {
        tokio::time::sleep(Duration::from_millis(150)).await;
        stream.write_all(piece).await.expect("a piece");
    }
    let seen = closed_within(&mut stream, Duration::from_secs(3)).await;
    assert!(
        seen.as_deref()
            .is_some_and(|answer| answer.ends_with("read 4")),
        "{seen:?}"
    );
}

#[tokio::test]
async fn a_listener_holds_at_most_its_connections_and_takes_the_next_when_one_closes() {
    let (address, _stop, _server) = quick(echo(), None).await;
    let mut held = Vec::new();
    for _ in 0..2 {
        held.push(TcpStream::connect(&address).await.expect("connects"));
    }
    // Both slots taken by connections that send nothing: a third is not served until one goes.
    let mut third = TcpStream::connect(&address)
        .await
        .expect("the kernel accepts it");
    third.write_all(REQUEST).await.expect("request sent");
    let mut first = [0_u8; 1];
    let early = tokio::time::timeout(Duration::from_millis(150), third.read(&mut first)).await;
    assert!(early.is_err(), "served beyond the connection limit");
    drop(held);
    let seen = closed_within(&mut third, Duration::from_secs(3)).await;
    assert!(
        seen.as_deref()
            .is_some_and(|answer| answer.ends_with("served")),
        "{seen:?}"
    );
}

#[tokio::test]
async fn shutdown_finishes_the_request_in_flight_and_accepts_no_more() {
    let slow = axum::Router::new().route(
        "/",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            "finished"
        }),
    );
    let (address, stop, server) = quick(slow, None).await;
    let mut stream = TcpStream::connect(&address).await.expect("connects");
    stream.write_all(REQUEST).await.expect("request sent");
    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.send(()).expect("the server listens");
    let seen = closed_within(&mut stream, Duration::from_secs(3)).await;
    assert!(
        seen.as_deref()
            .is_some_and(|answer| answer.ends_with("finished")),
        "{seen:?}"
    );
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .expect("the server stops once drained")
        .expect("the server ends without panicking");
    assert!(
        TcpStream::connect(&address).await.is_err(),
        "the listener is closed"
    );
}
