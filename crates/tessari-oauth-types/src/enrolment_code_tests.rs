use super::EnrolmentCode;

#[test]
fn the_digest_is_base64url_sha256_of_the_value() {
    // The RFC 7636 Appendix B pair is a published SHA-256 → base64url vector over an ASCII string.
    let code = EnrolmentCode::from_secret("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert_eq!(code.digest(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
}

#[test]
fn debug_formatting_never_shows_the_value() {
    let code = EnrolmentCode::from_secret("SplxlOBeZQQYbYS6WxSbIA");
    let printed = format!("{code:?}");
    assert!(!printed.contains("SplxlOBeZQQYbYS6WxSbIA"), "{printed}");
}
