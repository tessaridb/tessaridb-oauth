use super::SigninKeys;

const PEPPER: [u8; 32] = [3; 32];

fn keys() -> SigninKeys {
    SigninKeys::from_pepper(&PEPPER).expect("derived")
}

#[test]
fn a_key_is_a_fixed_digest_of_its_parts_naming_none_of_them() {
    let keys = keys();
    let account = keys.account("acme", "ada@example.com");
    assert_eq!(account, keys.account("acme", "ada@example.com"), "stable");
    assert_eq!(account.len(), 43, "SHA-256, base64url");
    assert!(!account.contains("ada"));
    let pair = keys.pair("acme", "ada@example.com", "correct horse battery staple");
    assert_eq!(pair.len(), 43);
    assert!(!pair.contains("horse"));
    assert_ne!(pair, account);
}

#[test]
fn every_part_and_the_pepper_change_the_key() {
    let keys = keys();
    let pair = keys.pair("acme", "ada@example.com", "pw-one-two-three");
    for (other, case) in [
        (
            keys.pair("globex", "ada@example.com", "pw-one-two-three"),
            "tenant",
        ),
        (
            keys.pair("acme", "bob@example.com", "pw-one-two-three"),
            "address",
        ),
        (
            keys.pair("acme", "ada@example.com", "pw-one-two-four"),
            "password",
        ),
        (
            SigninKeys::from_pepper(&[4; 32]).expect("derived").pair(
                "acme",
                "ada@example.com",
                "pw-one-two-three",
            ),
            "pepper",
        ),
    ] {
        assert_ne!(other, pair, "{case}");
    }
    assert_ne!(
        keys.account("acme", "ada@example.com"),
        keys.account("globex", "ada@example.com"),
        "tenant"
    );
    // Lengths are written before each part, so moving the boundary between two parts is a different key.
    assert_ne!(keys.account("acme", "a@b.c"), keys.account("acmea", "@b.c"));
}

#[test]
fn a_password_is_compared_in_normalization_form_c() {
    let keys = keys();
    // U+00E9 against U+0065 U+0301: one character typed two ways.
    assert_eq!(
        keys.pair("acme", "ada@example.com", "caf\u{e9}-au-lait-noir"),
        keys.pair("acme", "ada@example.com", "cafe\u{301}-au-lait-noir")
    );
}

#[test]
fn the_keys_match_an_independent_derivation() {
    // HKDF-SHA-256 (empty salt, the label as info, one block), then HMAC-SHA-256 over length-prefixed parts, computed
    // with Python's standard `hmac` and `hashlib` for this pepper.
    let keys = keys();
    assert_eq!(
        keys.account("acme", "ada@example.com"),
        "8B5VDL7UU2q_eW-MhoNPIj-oNorFzeJb_uJyMcW9iQA"
    );
    assert_eq!(
        keys.pair("acme", "ada@example.com", "correct horse battery staple"),
        "bnFlnZumnsp6-8tJyf0lTO_FJxZ2s-UdweG1nmY0Mnk"
    );
}
