//! `prompt` (OpenID Connect Core §3.1.2.1): `none` asks that no page be shown, and cannot be combined.

use tessari_oauth_types::ErrorCode;

use super::tests::{redirected, run, valid, with};
use crate::Reason;

#[test]
fn a_request_is_silent_only_when_prompt_is_none_alone() {
    assert!(!run(valid()).expect("valid").silent, "no prompt");
    assert!(run(with("prompt", "none")).expect("valid").silent);
    for prompt in ["login", "consent", "select_account", "login consent"] {
        assert!(
            !run(with("prompt", prompt)).expect("valid").silent,
            "{prompt}"
        );
    }
}

#[test]
fn a11_none_combined_with_another_value_is_redirected() {
    for prompt in ["none login", "consent none", "none none"] {
        assert_eq!(
            redirected(with("prompt", prompt)),
            (ErrorCode::InvalidRequest, Reason::PromptNoneCombined),
            "{prompt}"
        );
    }
}
