use super::KeyThumbprint;
use crate::Error;

/// The thumbprint RFC 7638 §3.1 computes for its example RSA key.
const RFC_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

#[test]
fn the_published_thumbprint_reads_back_unchanged() {
    let thumbprint = KeyThumbprint::parse(RFC_THUMBPRINT).expect("the RFC's own thumbprint parses");
    assert_eq!(thumbprint.as_str(), RFC_THUMBPRINT);
}

#[test]
fn anything_but_43_base64url_characters_is_refused() {
    for raw in [
        String::new(),
        RFC_THUMBPRINT[1..].to_owned(),
        format!("{RFC_THUMBPRINT}A"),
        RFC_THUMBPRINT.replacen('-', "+", 1).replacen('_', "/", 1),
        format!("{}=", &RFC_THUMBPRINT[..42]),
    ] {
        assert!(
            matches!(
                KeyThumbprint::parse(raw.clone()),
                Err(Error::Invalid { field: "jkt", .. })
            ),
            "{raw:?} should be refused as a thumbprint"
        );
    }
}

#[test]
fn the_thumbprint_of_a_canonical_jwk_is_its_sha256_in_base64url() {
    // RFC 8037 §A.3: the canonical members of its Ed25519 key and the thumbprint they hash to.
    let canonical =
        r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    assert_eq!(
        KeyThumbprint::of_canonical_jwk(canonical).as_str(),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}
