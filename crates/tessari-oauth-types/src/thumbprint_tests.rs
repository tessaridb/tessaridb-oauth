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
