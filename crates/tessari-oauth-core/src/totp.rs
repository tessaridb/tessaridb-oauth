//! Time-based one-time codes (RFC 6238) as a second factor.
//!
//! HMAC-SHA-1 over the 30-second step count, dynamically truncated to six digits (RFC 4226 §5.3) — the parameters
//! every authenticator app implements. A code is accepted for its own step or one step either side, to absorb a clock
//! or a slow typist, and never for a step at or before the last one accepted, so one code signs in once. Every step
//! in the window is computed and compared in constant time, so the answer's timing says nothing about which matched.

use ring::hmac;
use subtle::ConstantTimeEq as _;
use tessari_oauth_constants::{TOTP_DIGITS, TOTP_SKEW_STEPS, TOTP_STEP_SECS};
use tessari_oauth_types::Timestamp;

/// Ten to the power of [`TOTP_DIGITS`]: what the truncated value is reduced modulo.
const MODULUS: u32 = 1_000_000;

/// Why a presented code was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpRefused {
    /// Not six digits.
    #[error("the code is not six digits")]
    Malformed,
    /// Not the code of any step in the window.
    #[error("the code is wrong")]
    Wrong,
    /// The code of a step already used.
    #[error("the code was already used")]
    Replayed,
}

/// The code of `secret` for time step `step`.
#[must_use]
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let digest = tag.as_ref();
    // The low four bits of the last byte choose where four bytes are read from (RFC 4226 §5.3).
    let offset = usize::from(digest.last().copied().unwrap_or(0) & 0x0f);
    let value = digest
        .iter()
        .skip(offset)
        .take(4)
        .fold(0_u32, |value, byte| {
            value.wrapping_shl(8) | u32::from(*byte)
        })
        & 0x7fff_ffff;
    value.checked_rem(MODULUS).unwrap_or(value)
}

/// `code` written as the user sees it: zero-padded to six digits.
fn shown(code: u32) -> String {
    format!("{code:0width$}", width = TOTP_DIGITS)
}

/// The step `presented` is the code of, when it is accepted at `now` after `last_step` was the last one used.
///
/// # Errors
///
/// [`TotpRefused`] naming why it was not.
pub fn verify(
    secret: &[u8],
    presented: &str,
    now: Timestamp,
    last_step: Option<u64>,
) -> Result<u64, TotpRefused> {
    let digits = shown(0).len();
    if presented.len() != digits || !presented.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TotpRefused::Malformed);
    }
    let current = now.unix_secs().checked_div(TOTP_STEP_SECS).unwrap_or(0);
    let mut matched = None;
    for step in current.saturating_sub(TOTP_SKEW_STEPS)..=current.saturating_add(TOTP_SKEW_STEPS) {
        let equal: bool = shown(code_at(secret, step))
            .as_bytes()
            .ct_eq(presented.as_bytes())
            .into();
        if equal && matched.is_none() {
            matched = Some(step);
        }
    }
    match matched {
        None => Err(TotpRefused::Wrong),
        Some(step) if last_step.is_some_and(|last| step <= last) => Err(TotpRefused::Replayed),
        Some(step) => Ok(step),
    }
}

#[cfg(test)]
#[path = "totp_tests.rs"]
mod tests;
