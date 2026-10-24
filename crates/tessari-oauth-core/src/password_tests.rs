use tessari_oauth_constants::{
    PASSWORD_MAX_CHARS, PASSWORD_MIN_CHARS_ALONE, PASSWORD_MIN_CHARS_WITHIN_MFA,
};

use super::{PasswordRefused, Usage, accept};

fn nothing_blocked(_: &str) -> bool {
    false
}

fn check(candidate: &str, usage: Usage) -> Result<String, PasswordRefused> {
    accept(candidate, usage, nothing_blocked, &[])
}

#[test]
fn the_length_depends_on_how_the_password_is_used() {
    let alone = "a".repeat(PASSWORD_MIN_CHARS_ALONE);
    assert_eq!(check(&alone, Usage::Alone), Ok(alone.clone()));
    assert_eq!(
        check(&alone[1..], Usage::Alone),
        Err(PasswordRefused::TooShort)
    );
    let within = "a".repeat(PASSWORD_MIN_CHARS_WITHIN_MFA);
    assert!(check(&within, Usage::WithinMfa).is_ok());
    assert_eq!(
        check(&within[1..], Usage::WithinMfa),
        Err(PasswordRefused::TooShort)
    );
    let longest = "a".repeat(PASSWORD_MAX_CHARS);
    assert!(check(&longest, Usage::Alone).is_ok());
    assert_eq!(
        check(&format!("{longest}a"), Usage::Alone),
        Err(PasswordRefused::TooLong)
    );
}

#[test]
fn characters_are_counted_after_normalisation_form_c() {
    // Fifteen two-byte letters are fifteen characters.
    assert!(check(&"ä".repeat(PASSWORD_MIN_CHARS_ALONE), Usage::Alone).is_ok());
    // A letter and a combining mark compose into one character, and the password kept is the composed form.
    let decomposed = "a\u{0308}".repeat(PASSWORD_MIN_CHARS_WITHIN_MFA);
    assert_eq!(
        check(&decomposed, Usage::WithinMfa),
        Ok("ä".repeat(PASSWORD_MIN_CHARS_WITHIN_MFA))
    );
    assert_eq!(
        check(&decomposed, Usage::Alone),
        Err(PasswordRefused::TooShort),
        "sixteen code points as typed, eight after composition"
    );
}

#[test]
fn any_printable_character_and_spaces_are_allowed_and_control_characters_are_not() {
    assert!(check("correct horse battery staple", Usage::Alone).is_ok());
    assert!(check("пароль-из-пятнадцати", Usage::Alone).is_ok());
    for control in ['\u{0}', '\u{7}', '\n', '\u{7f}', '\u{9b}'] {
        let candidate = format!("correct horse{control}battery");
        assert_eq!(
            check(&candidate, Usage::Alone),
            Err(PasswordRefused::NotPrintable),
            "{control:?}"
        );
    }
}

#[test]
fn a_blocked_value_or_a_context_word_is_refused_whole_and_case_folded() {
    let blocked = |value: &str| value == "passwordpassword1";
    assert_eq!(
        accept("PasswordPassword1", Usage::Alone, blocked, &[]),
        Err(PasswordRefused::Guessable)
    );
    assert!(accept("passwordpassword1 extra", Usage::Alone, blocked, &[]).is_ok());
    let context = ["tessaridb-oauth-acme", "alice.wonderland@example.com"];
    assert_eq!(
        accept(
            "Alice.Wonderland@Example.com",
            Usage::Alone,
            nothing_blocked,
            &context
        ),
        Err(PasswordRefused::Guessable)
    );
    assert!(
        accept(
            "alice.wonderland@example.com!",
            Usage::Alone,
            nothing_blocked,
            &context
        )
        .is_ok()
    );
}
