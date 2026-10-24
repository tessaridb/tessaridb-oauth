use super::RefreshToken;

#[test]
fn the_digest_is_base64url_sha256_of_the_token() {
    // The RFC 7636 Appendix B pair is a published SHA-256 → base64url vector over an ASCII string.
    let token = RefreshToken::from_secret("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert_eq!(
        token.digest(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn debug_formatting_never_shows_the_token() {
    let token = RefreshToken::from_secret("tGzv3JOkF0XG5Qx2TlKWIA");
    let printed = format!("{token:?}");
    assert!(!printed.contains("tGzv3JOkF0XG5Qx2TlKWIA"), "{printed}");
}
