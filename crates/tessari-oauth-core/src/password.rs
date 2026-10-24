//! The rules a new password must meet (NIST SP 800-63B-4 §3.1.1.2): long enough for how it is used, any printable
//! characters including spaces, no composition rule, and not a value an attacker tries first. The value is compared
//! and later hashed in Normalization Form C, and is never echoed in a refusal.

use tessari_oauth_constants::{
    PASSWORD_MAX_CHARS, PASSWORD_MIN_CHARS_ALONE, PASSWORD_MIN_CHARS_WITHIN_MFA,
};
use unicode_normalization::UnicodeNormalization;

/// How the password is used, which decides how long it must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// The password is the only factor.
    Alone,
    /// The password is used only together with another factor.
    WithinMfa,
}

/// Why a new password was refused; the value itself is never carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordRefused {
    /// Fewer characters than its usage requires.
    #[error("the password is too short")]
    TooShort,
    /// More characters than are accepted.
    #[error("the password is too long")]
    TooLong,
    /// A control character.
    #[error("the password holds a character that is not printable")]
    NotPrintable,
    /// A commonly used, expected or compromised value, or a word of the account's own context.
    #[error("the password is too easily guessed")]
    Guessable,
}

/// `candidate` in Normalization Form C when it may be set as a password for `usage`: neither `blocked` (the
/// blocklist, asked about the case-folded value) nor equal to one of the `context` words.
///
/// # Errors
///
/// The first rule `candidate` breaks.
pub fn accept(
    candidate: &str,
    usage: Usage,
    blocked: impl Fn(&str) -> bool,
    context: &[&str],
) -> Result<String, PasswordRefused> {
    let normalised: String = candidate.nfc().collect();
    let length = normalised.chars().count();
    let shortest = match usage {
        Usage::Alone => PASSWORD_MIN_CHARS_ALONE,
        Usage::WithinMfa => PASSWORD_MIN_CHARS_WITHIN_MFA,
    };
    if length < shortest {
        return Err(PasswordRefused::TooShort);
    }
    if length > PASSWORD_MAX_CHARS {
        return Err(PasswordRefused::TooLong);
    }
    if normalised.chars().any(char::is_control) {
        return Err(PasswordRefused::NotPrintable);
    }
    let folded = normalised.to_lowercase();
    let in_context = context.iter().any(|word| word.to_lowercase() == folded);
    if in_context || blocked(&folded) {
        return Err(PasswordRefused::Guessable);
    }
    Ok(normalised)
}

#[cfg(test)]
#[path = "password_tests.rs"]
mod tests;
