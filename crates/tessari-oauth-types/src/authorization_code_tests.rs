use super::AuthorizationCode;

#[test]
fn the_digest_is_base64url_sha256_of_the_code() {
    // The RFC 7636 Appendix B pair is a published SHA-256 → base64url vector over an ASCII string.
    let code = AuthorizationCode::from_secret("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert_eq!(code.digest(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
}

#[test]
fn debug_formatting_never_shows_the_code() {
    let code = AuthorizationCode::from_secret("SplxlOBeZQQYbYS6WxSbIA");
    let printed = format!("{code:?}");
    assert!(!printed.contains("SplxlOBeZQQYbYS6WxSbIA"), "{printed}");
}
