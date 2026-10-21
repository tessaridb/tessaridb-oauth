use super::{encode, is_alphabet};

#[test]
fn encodes_the_rfc_4648_vectors_without_padding() {
    // RFC 4648 §10 test vectors, with the padding the standard alphabet would add removed.
    for (input, expected) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(encode(input.as_bytes()), expected, "{input:?}");
    }
}

#[test]
fn uses_the_url_safe_characters_for_the_last_two_slots() {
    // 0xfb 0xff encodes to the 62nd and 63rd characters, which differ between the two alphabets.
    assert_eq!(encode(&[0xfb, 0xff]), "-_8");
}

#[test]
fn the_alphabet_check_refuses_padding_and_the_standard_alphabet() {
    assert!(is_alphabet("Zm9vYmFy-_"));
    assert!(!is_alphabet("Zm9vYg=="), "padding is not base64url");
    assert!(
        !is_alphabet("ab+/"),
        "`+` and `/` belong to the standard alphabet"
    );
}
