use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use tessari_oauth_types::EmailAddress;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::MailRelay;
use crate::Error;
use crate::config::{MailCredentials, MailSecurity, MailSettings};
use crate::mail::OutgoingMail;

const TIMEOUT: Duration = Duration::from_secs(5);

/// How the scripted relay answers.
#[derive(Clone, Copy)]
enum Script {
    /// Takes every mail.
    Accepts,
    /// Refuses the recipient with a permanent failure.
    RefusesRecipient,
}

/// A relay on 127.0.0.1 that answers one connection by `script`, offering no STARTTLS, and hands back every line
/// the client sent.
async fn scripted_relay(script: Script) -> (u16, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let task = tokio::spawn(async move {
        let mut received = Vec::new();
        let Ok((stream, _)) = listener.accept().await else {
            return received;
        };
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let _ = writer.write_all(b"220 relay.test ESMTP\r\n").await;
        let mut in_data = false;
        while let Ok(Some(line)) = lines.next_line().await {
            received.push(line.clone());
            let answer: &[u8] = if in_data {
                if line == "." {
                    in_data = false;
                    b"250 queued\r\n"
                } else {
                    continue;
                }
            } else {
                let verb = line.to_ascii_uppercase();
                if verb.starts_with("EHLO") {
                    b"250-relay.test\r\n250 8BITMIME\r\n"
                } else if verb.starts_with("MAIL FROM") {
                    b"250 ok\r\n"
                } else if verb.starts_with("RCPT TO") {
                    match script {
                        Script::Accepts => b"250 ok\r\n",
                        Script::RefusesRecipient => b"550 no such mailbox\r\n",
                    }
                } else if verb == "DATA" {
                    in_data = true;
                    b"354 go ahead\r\n"
                } else if verb == "QUIT" {
                    let _ = writer.write_all(b"221 bye\r\n").await;
                    break;
                } else {
                    b"250 ok\r\n"
                }
            };
            if writer.write_all(answer).await.is_err() {
                break;
            }
        }
        received
    });
    (port, task)
}

/// What the scripted relay received, or nothing when no client connected within the timeout.
async fn transcript(relay: JoinHandle<Vec<String>>) -> Vec<String> {
    match tokio::time::timeout(TIMEOUT, relay).await {
        Ok(received) => received.expect("the relay ran"),
        Err(_) => Vec::new(),
    }
}

fn settings(port: u16, security: MailSecurity) -> MailSettings {
    MailSettings {
        host: "127.0.0.1".to_owned(),
        port,
        security,
        credentials: None,
        from_name: Some("Acme sign-in".to_owned()),
        from_address: "no-reply@id.example.com".to_owned(),
        authority: None,
    }
}

fn mail() -> OutgoingMail {
    OutgoingMail {
        to: EmailAddress::parse("ada@example.com").expect("an address"),
        subject: "Reset your password".to_owned(),
        text: "Open the link to choose a new password.".to_owned(),
    }
}

/// A file holding `content` with `mode`, in a directory of its own that the caller removes.
fn secret_file(name: &str, content: &str, mode: u32) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("tessari-oauth-relay-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a directory");
    let path = directory.join("file");
    std::fs::write(&path, content).expect("written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode set");
    path
}

#[tokio::test]
async fn a_mail_reaches_the_relay_with_its_envelope_and_text() {
    let (port, relay) = scripted_relay(Script::Accepts).await;
    let sender =
        MailRelay::load(&settings(port, MailSecurity::PlainLoopback), TIMEOUT).expect("a relay");

    sender.send(&mail()).await.expect("sent");

    let received = transcript(relay).await;
    assert!(
        received
            .iter()
            .any(|line| line == "MAIL FROM:<no-reply@id.example.com>"),
        "{received:?}"
    );
    assert!(
        received
            .iter()
            .any(|line| line == "RCPT TO:<ada@example.com>"),
        "{received:?}"
    );
    assert!(
        received
            .iter()
            .any(|line| line == "Subject: Reset your password"),
        "{received:?}"
    );
    assert!(
        received
            .iter()
            .any(|line| line == "Open the link to choose a new password."),
        "{received:?}"
    );
}

#[tokio::test]
async fn a_refused_recipient_is_a_failed_send() {
    let (port, relay) = scripted_relay(Script::RefusesRecipient).await;
    let sender =
        MailRelay::load(&settings(port, MailSecurity::PlainLoopback), TIMEOUT).expect("a relay");

    let outcome = sender.send(&mail()).await;

    assert!(matches!(outcome, Err(Error::Mail { .. })), "{outcome:?}");
    let received = transcript(relay).await;
    assert!(
        received
            .iter()
            .any(|line| line == "RCPT TO:<ada@example.com>"),
        "the relay was asked: {received:?}"
    );
    assert!(
        !received.iter().any(|line| line == "DATA"),
        "no text after a refusal: {received:?}"
    );
}

#[tokio::test]
async fn starttls_is_required_so_a_relay_without_it_is_never_given_the_mail() {
    let (port, relay) = scripted_relay(Script::Accepts).await;
    let key = rcgen::KeyPair::generate().expect("a key");
    let authority = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("a certificate");
    let authority = secret_file("authority", &authority.pem(), 0o600);
    let mut starttls = settings(port, MailSecurity::StartTls);
    starttls.authority = Some(authority.clone());
    let sender = MailRelay::load(&starttls, TIMEOUT).expect("a relay");
    if let Some(directory) = authority.parent() {
        std::fs::remove_dir_all(directory).expect("removed");
    }

    let outcome = sender.send(&mail()).await;

    assert!(matches!(outcome, Err(Error::Mail { .. })), "{outcome:?}");
    let received = transcript(relay).await;
    assert!(
        received.iter().any(|line| line.starts_with("EHLO")),
        "the relay was reached: {received:?}"
    );
    assert!(
        !received
            .iter()
            .any(|line| line.to_ascii_uppercase().starts_with("MAIL FROM")),
        "nothing sent in the clear: {received:?}"
    );
}

#[test]
fn a_password_file_others_can_read_is_refused() {
    let path = secret_file("shared", "s3cret", 0o644);
    let mut relay = settings(2525, MailSecurity::PlainLoopback);
    relay.credentials = Some(MailCredentials {
        user: "mailer".to_owned(),
        password_file: path.clone(),
    });

    let outcome = MailRelay::load(&relay, TIMEOUT);

    if let Some(directory) = path.parent() {
        std::fs::remove_dir_all(directory).expect("removed");
    }
    assert!(
        matches!(
            outcome,
            Err(Error::InvalidConfig {
                field: "smtp_password_file",
                ..
            })
        ),
        "{:?}",
        outcome.err()
    );
}
