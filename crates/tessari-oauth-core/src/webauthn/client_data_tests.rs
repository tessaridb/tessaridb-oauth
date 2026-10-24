use super::super::authenticator::{CHALLENGE, ORIGIN, client_data};
use super::super::challenge_of;

#[test]
fn the_challenge_is_read_out_of_the_client_data() {
    assert_eq!(
        challenge_of(&client_data("webauthn.get", CHALLENGE, ORIGIN)),
        Some(CHALLENGE.to_vec())
    );
    for (unreadable, case) in [
        (b"not json".to_vec(), "not JSON"),
        (
            br#"{"type":"webauthn.get","origin":"x"}"#.to_vec(),
            "no challenge",
        ),
        (
            br#"{"type":"webauthn.get","challenge":"a b","origin":"x"}"#.to_vec(),
            "not base64url",
        ),
        (oversized(), "larger than any browser sends"),
    ] {
        assert_eq!(challenge_of(&unreadable), None, "{case}");
    }
}

/// Readable client data, padded past the largest part any browser sends.
fn oversized() -> Vec<u8> {
    let mut json = client_data("webauthn.get", CHALLENGE, ORIGIN);
    json.pop();
    json.extend_from_slice(br#","padding":""#);
    json.extend(std::iter::repeat_n(b'a', 70_000));
    json.extend_from_slice(br#""}"#);
    json
}
