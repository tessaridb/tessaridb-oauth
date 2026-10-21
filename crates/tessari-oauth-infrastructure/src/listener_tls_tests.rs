use super::{ListenerTls, listener_config};
use crate::Error;

fn pair(name: &str) -> (String, String) {
    let key = rcgen::KeyPair::generate().expect("a key");
    let certificate = rcgen::CertificateParams::new(vec![name.to_owned()])
        .expect("parameters")
        .self_signed(&key)
        .expect("a certificate");
    (certificate.pem(), key.serialize_pem())
}

fn field_of(refused: Error) -> &'static str {
    match refused {
        Error::InvalidConfig { field, .. } => field,
        other => panic!("not a configuration refusal: {other:?}"),
    }
}

#[test]
fn a_certificate_and_its_key_make_a_listener_configuration() {
    let (certificate, key) = pair("localhost");
    listener_config(&ListenerTls::new(
        certificate.into_bytes(),
        key.into_bytes(),
    ))
    .expect("a configuration");
}

#[test]
fn a_key_of_another_certificate_is_refused() {
    let (certificate, _) = pair("localhost");
    let (_, other_key) = pair("localhost");
    let refused = listener_config(&ListenerTls::new(
        certificate.into_bytes(),
        other_key.into_bytes(),
    ))
    .expect_err("a mismatched key");
    assert_eq!(field_of(refused), "tls_key");
}

#[test]
fn a_chain_without_a_certificate_and_a_missing_key_are_refused() {
    let (certificate, key) = pair("localhost");
    let empty = listener_config(&ListenerTls::new(Vec::new(), key.into_bytes()))
        .expect_err("no certificate");
    assert_eq!(field_of(empty), "tls_certificate");
    let keyless = listener_config(&ListenerTls::new(certificate.into_bytes(), Vec::new()))
        .expect_err("no key");
    assert_eq!(field_of(keyless), "tls_key");
}

#[test]
fn the_key_is_not_printed() {
    let (certificate, key) = pair("localhost");
    let printed = format!(
        "{:?}",
        ListenerTls::new(certificate.into_bytes(), key.clone().into_bytes())
    );
    assert!(!printed.contains("PRIVATE KEY"), "{printed}");
    assert!(!printed.contains(&key[40..80]), "{printed}");
}
