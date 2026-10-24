//! Enrolment over a live store: a code an operator issued lets its user set a first password once; an unknown or
//! spent code is refused alike; a refused password leaves the code usable; an account with a password keeps it; a
//! password the breached-password list holds is refused, and an unanswered lookup refuses nothing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::json;
use tessari_oauth_api::public_router;
use tessari_oauth_infrastructure::breached::BreachedPasswords;
use tessari_oauth_infrastructure::custody::Verdict;
use tessari_oauth_types::{EnrolmentCode, Timestamp, UserId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::login::{KNOWN, post, register};
use crate::login_password::{RIGHT, with_password};
use crate::routes::{Answer, answer};
use crate::token_fixture::{BROWSER_COOKIE, NOW, Server, passwords, plenty, server, state, tenant};

const NEW: &str = "a long enough first password for ada";

async fn issued(server: &Server, user: &UserId, code: &str) {
    server
        .storage
        .enrolments
        .issue(
            &tenant("acme"),
            &EnrolmentCode::from_secret(code),
            user,
            "operator-1",
            Timestamp::from_unix_secs(NOW),
        )
        .await
        .expect("issued");
}

/// Whether `password` is the stored password of `user`.
async fn holds(server: &Server, user: &UserId, password: &str) -> bool {
    let stored = server
        .storage
        .users
        .password(&tenant("acme"), user)
        .await
        .expect("an answer");
    let Some(stored) = stored else { return false };
    matches!(
        passwords()
            .verify(password, Some(&stored.hash))
            .await
            .expect("verified"),
        Verdict::Match { .. }
    )
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_code_sets_the_first_password_once() {
    let server = server(2).await;
    let user = register(&server, KNOWN).await;
    issued(&server, &user, "code-1").await;
    let enrolled = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": NEW }),
    )
    .await;
    assert_eq!(enrolled.status, StatusCode::NO_CONTENT);
    assert!(holds(&server, &user, NEW).await);
    let again = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": NEW }),
    )
    .await;
    let unknown = post(
        &server,
        "enroll",
        None,
        json!({ "code": "never", "password": NEW }),
    )
    .await;
    for refused in [&again, &unknown] {
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(refused.body["code"], "code_rejected");
    }
    assert_eq!(
        again.body, unknown.body,
        "a spent code and an unknown one read alike"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_refused_password_leaves_the_code_usable() {
    let server = server(2).await;
    let user = register(&server, KNOWN).await;
    issued(&server, &user, "code-1").await;
    let short = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": "short" }),
    )
    .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    assert_eq!(short.body["code"], "password_rejected");
    assert!(!holds(&server, &user, "short").await);
    let enrolled = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": NEW }),
    )
    .await;
    assert_eq!(enrolled.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_account_with_a_password_keeps_it() {
    let server = server(2).await;
    let user = with_password(&server, KNOWN).await;
    issued(&server, &user, "code-1").await;
    let refused = post(
        &server,
        "enroll",
        None,
        json!({ "code": "code-1", "password": NEW }),
    )
    .await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.body["code"], "already_enrolled");
    assert!(holds(&server, &user, RIGHT).await);
    assert!(!holds(&server, &user, NEW).await);
}

/// An HTTPS range service on 127.0.0.1 listing `listed` as seen in breaches, its base URL and the root it is signed by.
async fn breached_list(listed: &str) -> (String, RootCertStore) {
    let hex: String = digest(&SHA1_FOR_LEGACY_USE_ONLY, listed.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    let body = format!("{}:12\r\n", &hex[5..]);
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
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
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let base = format!(
        "https://127.0.0.1:{}/range/",
        listener.local_addr().expect("an address").port()
    );
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
            let _ = tls.write_all(response.as_bytes()).await;
            let _ = tls.shutdown().await;
        }
    });
    (base, roots)
}

/// POST an enrolment of `code` with `password` to a server that looks new passwords up at `breached`.
async fn enrol_checked(
    server: &Server,
    breached: Arc<BreachedPasswords>,
    code: &str,
    password: &str,
) -> Answer {
    let mut public = state(server, plenty());
    public.breached = Some(breached);
    let request = Request::post("/acme/login/api/enroll")
        .header("content-type", "application/json")
        .header("cookie", BROWSER_COOKIE)
        .extension(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 4000))))
        .body(Body::from(
            json!({ "code": code, "password": password }).to_string(),
        ))
        .expect("a request");
    let response = public_router(public)
        .oneshot(request)
        .await
        .expect("the router answers");
    answer(response).await
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_password_seen_in_a_breach_is_refused_and_the_code_stays_usable() {
    let server = server(2).await;
    let user = register(&server, KNOWN).await;
    issued(&server, &user, "code-1").await;
    let (base, roots) = breached_list(NEW).await;
    let lookups = Arc::new(
        BreachedPasswords::new(&base, roots, Duration::from_secs(10)).expect("a lookup service"),
    );
    let seen = enrol_checked(&server, Arc::clone(&lookups), "code-1", NEW).await;
    assert_eq!(seen.status, StatusCode::BAD_REQUEST);
    assert_eq!(seen.body["code"], "password_rejected");
    assert!(!holds(&server, &user, NEW).await);
    let other = "another long first password for ada";
    let enrolled = enrol_checked(&server, lookups, "code-1", other).await;
    assert_eq!(enrolled.status, StatusCode::NO_CONTENT);
    assert!(holds(&server, &user, other).await);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_lookup_that_does_not_answer_refuses_nothing() {
    let server = server(2).await;
    let user = register(&server, KNOWN).await;
    issued(&server, &user, "code-1").await;
    // A port nothing listens on: the lookup cannot connect.
    let closed = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = closed.local_addr().expect("an address").port();
    drop(closed);
    let lookups = Arc::new(
        BreachedPasswords::new(
            &format!("https://127.0.0.1:{port}/range/"),
            RootCertStore::empty(),
            Duration::from_secs(2),
        )
        .expect("a lookup service"),
    );
    let enrolled = enrol_checked(&server, lookups, "code-1", NEW).await;
    assert_eq!(enrolled.status, StatusCode::NO_CONTENT);
    assert!(holds(&server, &user, NEW).await);
}
