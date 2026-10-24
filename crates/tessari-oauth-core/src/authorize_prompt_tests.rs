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

#[test]
fn max_age_is_kept_and_prompt_login_asks_for_a_sign_in_now() {
    assert_eq!(run(valid()).expect("valid").max_age, None, "neither asked");
    assert_eq!(
        run(with("max_age", "300")).expect("valid").max_age,
        Some(300)
    );
    assert_eq!(run(with("max_age", "0")).expect("valid").max_age, Some(0));
    assert_eq!(
        run(with("prompt", "login")).expect("valid").max_age,
        Some(0)
    );
    assert_eq!(
        run(with("prompt", "consent login")).expect("valid").max_age,
        Some(0)
    );
    let mut both = with("prompt", "login");
    both.push(("max_age", "300".to_owned()));
    assert_eq!(run(both).expect("valid").max_age, Some(0), "the stricter");
}

#[test]
fn a_max_age_that_is_not_a_count_of_seconds_is_redirected() {
    for value in [
        "",
        "-1",
        "+300",
        "1.5",
        "300s",
        " 300",
        "99999999999999999999",
    ] {
        assert_eq!(
            redirected(with("max_age", value)),
            (ErrorCode::InvalidRequest, Reason::MaxAgeInvalid),
            "{value:?}"
        );
    }
}
