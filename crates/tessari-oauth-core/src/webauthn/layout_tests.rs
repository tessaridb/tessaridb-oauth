//! What surrounds a credential: the frame the response was made in, extension outputs after the key, nothing after
//! the last declared part, and an attestation object that names its format.

use super::authenticator::{
    AT, CHALLENGE, ORIGIN, RP_ID, Signer, UP, UV, attestation_object, authenticator_data,
    client_data,
};
use super::tests::{CREDENTIAL_ID, expected, registration};
use super::{WebauthnRefused, register};

/// Extension outputs an authenticator appends after the credential: `{"credProtect": 2}`.
const EXTENSIONS: &[u8] = b"\xa1\x6bcredProtect\x02";
/// Extension data included.
const ED: u8 = 0x80;
/// Backed up.
const BS: u8 = 0x10;

#[test]
fn a_registration_reads_past_extensions_and_refuses_what_the_layout_forbids() {
    let signer = Signer::ed25519();
    let key = signer.cose_key();
    let client = client_data("webauthn.create", CHALLENGE, ORIGIN);
    let mut extended = authenticator_data(RP_ID, UP | UV | AT | ED, 0, Some((CREDENTIAL_ID, &key)));
    extended.extend_from_slice(EXTENSIONS);
    assert_eq!(
        register(&client, &attestation_object(&extended), &expected(true)).map(|r| r.public_key),
        Ok(key.clone()),
        "the key ends where its CBOR item ends"
    );
    let mut trailing = authenticator_data(RP_ID, UP | UV | AT, 0, Some((CREDENTIAL_ID, &key)));
    trailing.extend_from_slice(EXTENSIONS);
    let long_id = vec![7_u8; 1024];
    let cases: [(&str, Vec<u8>); 3] = [
        ("bytes after the key with no extension flag", trailing),
        (
            "backed up but not backup eligible",
            authenticator_data(RP_ID, UP | UV | AT | BS, 0, Some((CREDENTIAL_ID, &key))),
        ),
        (
            "a credential id longer than the specification allows",
            authenticator_data(RP_ID, UP | UV | AT, 0, Some((&long_id, &key))),
        ),
    ];
    for (case, data) in cases {
        assert_eq!(
            register(&client, &attestation_object(&data), &expected(true)),
            Err(WebauthnRefused::AuthenticatorDataUnreadable),
            "{case}"
        );
    }
}

#[test]
fn an_attestation_object_names_its_format_and_ends_where_it_ends() {
    use coset::{CborSerializable as _, cbor::Value};

    let (client, attestation) = registration(&Signer::ed25519(), UP | UV | AT);
    let Ok(Value::Map(entries)) = Value::from_slice(&attestation) else {
        panic!("an attestation object is a map");
    };
    let renamed = |name: Option<&str>| {
        Value::Map(
            entries
                .iter()
                .filter_map(|(key, value)| match (key.as_text(), name) {
                    (Some("fmt"), None) => None,
                    (Some("fmt"), Some(name)) => {
                        Some((Value::Text(name.to_owned()), value.clone()))
                    }
                    _ => Some((key.clone(), value.clone())),
                })
                .collect(),
        )
        .to_vec()
        .expect("encodes")
    };
    let trailing = [&attestation[..], &[0]].concat();
    for (case, object) in [
        ("no format", renamed(None)),
        ("the format under another name", renamed(Some("format"))),
        ("a byte after the object", trailing),
    ] {
        assert_eq!(
            register(&client, &object, &expected(true)),
            Err(WebauthnRefused::AttestationUnreadable),
            "{case}"
        );
    }
}

#[test]
fn a_response_made_inside_a_frame_of_another_origin_is_refused() {
    let framed = String::from_utf8(client_data("webauthn.create", CHALLENGE, ORIGIN))
        .expect("text")
        .replace(r#""crossOrigin":false"#, r#""crossOrigin":true"#)
        .into_bytes();
    let (_, attestation) = registration(&Signer::ed25519(), UP | UV | AT);
    assert_eq!(
        register(&framed, &attestation, &expected(true)),
        Err(WebauthnRefused::CrossOrigin)
    );
}
