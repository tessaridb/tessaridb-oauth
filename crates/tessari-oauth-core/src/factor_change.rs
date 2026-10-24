//! Whether a session may change the account's sign-in factors: adding or removing a passkey, an authenticator app or
//! recovery codes, or the password. The sign-in behind the session must be recent, and when the account already holds
//! a second factor it must have reached the level that factor gives, so that a stolen password alone, or a session
//! left open, cannot replace what protects the account.

use tessari_oauth_constants::FACTOR_CHANGE_RECENCY_SECS;

use crate::authentication::Level;

/// Why a session may not change the account's factors yet; either way, the user signs in again first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorChangeRefused {
    /// The sign-in is older than the recency window.
    SignInTooOld,
    /// The account holds a second factor and the sign-in did not use one.
    LevelTooLow,
}

/// Whether a session whose sign-in reached `level` `signed_in_for` seconds ago may change the factors of an account
/// that `holds_second_factor` or not.
///
/// # Errors
///
/// [`FactorChangeRefused`] naming the first condition not met.
pub fn factor_change(
    level: Level,
    signed_in_for: u64,
    holds_second_factor: bool,
) -> Result<(), FactorChangeRefused> {
    if signed_in_for > FACTOR_CHANGE_RECENCY_SECS {
        return Err(FactorChangeRefused::SignInTooOld);
    }
    if holds_second_factor && level == Level::SingleFactor {
        return Err(FactorChangeRefused::LevelTooLow);
    }
    Ok(())
}

#[cfg(test)]
#[path = "factor_change_tests.rs"]
mod tests;
