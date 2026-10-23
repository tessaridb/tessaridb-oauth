use tessari_oauth_types::EmailAddress;

use super::{OutgoingMail, Sender};

fn sender() -> Sender {
    Sender {
        name: Some("Acme sign-in".to_owned()),
        address: "no-reply@id.example.com".to_owned(),
    }
}

fn mail(subject: &str) -> OutgoingMail {
    OutgoingMail {
        to: EmailAddress::parse("ada@example.com").expect("an address"),
        subject: subject.to_owned(),
        text: "Your code is 1234.\nIt works once.".to_owned(),
    }
}

fn formatted(mail: &OutgoingMail) -> String {
    String::from_utf8(mail.message(&sender()).expect("a message").formatted()).expect("text")
}

#[test]
fn a_mail_names_its_sender_and_recipient_and_carries_plain_text() {
    let text = formatted(&mail("Reset your password"));
    let headers: Vec<&str> = text
        .split("\r\n\r\n")
        .next()
        .expect("headers")
        .split("\r\n")
        .collect();
    assert!(
        headers
            .iter()
            .any(|line| line.starts_with("From: \"Acme sign-in\" <no-reply@id.example.com>")),
        "{text}"
    );
    assert!(headers.contains(&"To: ada@example.com"), "{text}");
    assert!(headers.contains(&"Subject: Reset your password"), "{text}");
    assert!(
        headers
            .iter()
            .any(|line| line.starts_with("Content-Type: text/plain; charset=utf-8")),
        "{text}"
    );
    assert!(text.contains("Your code is 1234."), "{text}");
}

#[test]
fn a_line_break_in_the_subject_never_starts_another_header() {
    let text = formatted(&mail("Reset\r\nBcc: thief@example.net"));
    let headers = text.split("\r\n\r\n").next().expect("headers");
    assert!(
        !headers
            .split("\r\n")
            .any(|line| line.to_ascii_lowercase().starts_with("bcc:")),
        "{headers}"
    );
}
