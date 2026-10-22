use super::{Assessment, Level, Method, assess};

const UV: Method = Method::Passkey {
    user_verified: true,
};
const UP: Method = Method::Passkey {
    user_verified: false,
};

fn assessed(level: Level, amr: &[&'static str]) -> Option<Assessment> {
    Some(Assessment {
        level,
        amr: amr.to_vec(),
    })
}

#[test]
fn each_combination_of_verified_methods_reaches_its_level_and_says_what_ran() {
    let table: [(&[Method], Option<Assessment>); 11] = [
        (&[], None),
        (&[Method::Password], assessed(Level::SingleFactor, &["pwd"])),
        (&[Method::Totp], assessed(Level::SingleFactor, &["otp"])),
        (&[UP], assessed(Level::SingleFactor, &["hwk"])),
        (&[UV], assessed(Level::PhishingResistant, &["hwk", "mfa"])),
        (
            &[Method::Password, Method::Totp],
            assessed(Level::MultiFactor, &["pwd", "otp", "mfa"]),
        ),
        (
            &[Method::Password, Method::RecoveryCode],
            assessed(Level::MultiFactor, &["pwd", "otp", "mfa"]),
        ),
        (
            &[Method::Password, UP],
            assessed(Level::MultiFactor, &["pwd", "hwk", "mfa"]),
        ),
        (
            &[Method::Password, UV],
            assessed(Level::PhishingResistant, &["pwd", "hwk", "mfa"]),
        ),
        (
            &[Method::Totp, Method::RecoveryCode],
            assessed(Level::SingleFactor, &["otp"]),
        ),
        (
            &[Method::Password, Method::Password],
            assessed(Level::SingleFactor, &["pwd"]),
        ),
    ];
    for (methods, expected) in table {
        assert_eq!(assess(methods), expected, "{methods:?}");
    }
}

#[test]
fn the_order_methods_ran_in_does_not_change_what_is_said() {
    assert_eq!(
        assess(&[Method::Totp, Method::Password]),
        assess(&[Method::Password, Method::Totp])
    );
    assert_eq!(
        assess(&[UV, Method::Password]),
        assess(&[Method::Password, UV])
    );
}

#[test]
fn the_levels_are_published_under_their_own_names() {
    assert_eq!(Level::SingleFactor.acr(), "urn:tessaridb:acr:sf");
    assert_eq!(Level::MultiFactor.acr(), "urn:tessaridb:acr:mfa");
    assert_eq!(Level::PhishingResistant.acr(), "urn:tessaridb:acr:phr");
    assert!(Level::SingleFactor < Level::MultiFactor);
    assert!(Level::MultiFactor < Level::PhishingResistant);
}
