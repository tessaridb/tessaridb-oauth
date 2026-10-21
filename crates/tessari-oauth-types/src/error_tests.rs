use crate::{Challenge, ErrorCategory, RedirectUri};

#[test]
fn a_refused_value_is_a_validation_failure_naming_its_parameter() {
    let pkce = Challenge::parse("short").expect_err("a short challenge is refused");
    assert_eq!(pkce.category(), ErrorCategory::Validation);
    assert_eq!(pkce.field(), "code_challenge");

    let redirect =
        RedirectUri::parse("http://app.example.com/cb").expect_err("http off loopback is refused");
    assert_eq!(redirect.category(), ErrorCategory::Validation);
    assert_eq!(redirect.field(), "redirect_uri");
}

#[test]
fn the_message_never_repeats_the_refused_value() {
    // A refusal is logged and may be shown to a developer; the value itself may be a verifier or a token.
    let verifier = "a-verifier-that-must-not-appear";
    let error = Challenge::of(verifier).expect_err("a short verifier is refused");
    assert!(!error.to_string().contains(verifier), "{error}");
}
