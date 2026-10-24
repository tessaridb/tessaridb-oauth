use super::{FactorChangeRefused, factor_change};
use crate::authentication::Level;

const RECENT: u64 = 600;

#[test]
fn a_change_needs_a_recent_sign_in_at_the_level_the_account_holds() {
    let table: [(Level, u64, bool, Result<(), FactorChangeRefused>); 9] = [
        (Level::SingleFactor, 0, false, Ok(())),
        (Level::SingleFactor, RECENT, false, Ok(())),
        (
            Level::SingleFactor,
            RECENT + 1,
            false,
            Err(FactorChangeRefused::SignInTooOld),
        ),
        (
            Level::SingleFactor,
            0,
            true,
            Err(FactorChangeRefused::LevelTooLow),
        ),
        (Level::MultiFactor, 0, true, Ok(())),
        (Level::PhishingResistant, 0, true, Ok(())),
        (
            Level::MultiFactor,
            RECENT + 1,
            true,
            Err(FactorChangeRefused::SignInTooOld),
        ),
        (Level::PhishingResistant, RECENT, true, Ok(())),
        (
            Level::SingleFactor,
            RECENT + 1,
            true,
            Err(FactorChangeRefused::SignInTooOld),
        ),
    ];
    for (level, signed_in_for, holds_second_factor, expected) in table {
        assert_eq!(
            factor_change(level, signed_in_for, holds_second_factor),
            expected,
            "{level:?} signed in {signed_in_for}s ago, second factor held: {holds_second_factor}"
        );
    }
}
