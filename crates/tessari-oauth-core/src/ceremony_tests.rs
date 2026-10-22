use tessari_oauth_types::UserId;

use super::{Ceremony, CeremonyRefused, Identity, Stage};
use crate::authentication::{Level, Method};

const UV: Method = Method::Passkey {
    user_verified: true,
};

fn user(name: &str) -> UserId {
    UserId::parse(name).expect("a user id")
}

fn known(name: &str, second_factor: bool) -> Identity {
    Identity::Known {
        user: user(name),
        second_factor,
    }
}

#[test]
fn a_password_alone_completes_an_account_without_a_second_factor() {
    let ceremony = Ceremony::new();
    assert_eq!(ceremony.stage(), Stage::Identify);
    let ceremony = ceremony.identify(known("u1", false)).expect("identified");
    assert_eq!(ceremony.stage(), Stage::FirstFactor);
    assert_eq!(ceremony.outcome(), None);
    let ceremony = ceremony.verified(Method::Password).expect("verified");
    assert_eq!(ceremony.stage(), Stage::Complete);
    let (signed_in, assessment) = ceremony.outcome().expect("an outcome");
    assert_eq!(signed_in, &user("u1"));
    assert_eq!(assessment.level, Level::SingleFactor);
}

#[test]
fn an_enrolled_second_factor_is_due_after_the_password() {
    let ceremony = Ceremony::new()
        .identify(known("u1", true))
        .and_then(|ceremony| ceremony.verified(Method::Password))
        .expect("first factor");
    assert_eq!(ceremony.stage(), Stage::SecondFactor);
    assert_eq!(ceremony.outcome(), None, "no outcome on one factor");
    for second in [Method::Totp, Method::RecoveryCode, UV] {
        let done = ceremony.clone().verified(second).expect("second factor");
        let (_, assessment) = done.outcome().expect("an outcome");
        assert!(assessment.level >= Level::MultiFactor, "{second:?}");
        assert!(assessment.amr.contains(&"mfa"), "{second:?}");
    }
}

#[test]
fn steps_out_of_their_stage_are_refused() {
    let fresh = Ceremony::new();
    assert_eq!(
        fresh.clone().verified(Method::Password),
        Err(CeremonyRefused::OutOfOrder),
        "a factor before identification"
    );
    let identified = fresh.identify(known("u1", true)).expect("identified");
    assert_eq!(
        identified.clone().identify(known("u2", false)),
        Err(CeremonyRefused::OutOfOrder),
        "identified twice"
    );
    assert_eq!(
        identified.clone().verified(Method::Totp),
        Err(CeremonyRefused::MethodNotAccepted),
        "a one-time code as the first factor"
    );
    let second = identified.verified(Method::Password).expect("first factor");
    assert_eq!(
        second.clone().verified(Method::Password),
        Err(CeremonyRefused::MethodNotAccepted),
        "the password again as the second factor"
    );
    assert_eq!(
        second.clone().passkey_sign_in(user("u2")),
        Err(CeremonyRefused::OutOfOrder),
        "a whole passkey sign-in after a first factor"
    );
    let done = second.verified(Method::Totp).expect("second factor");
    assert_eq!(
        done.clone().verified(Method::Totp),
        Err(CeremonyRefused::OutOfOrder),
        "a factor after the outcome"
    );
    assert_eq!(
        done.passkey_sign_in(user("u1")),
        Err(CeremonyRefused::OutOfOrder),
        "a passkey after the outcome"
    );
}

#[test]
fn an_unknown_identifier_moves_on_like_a_known_one_and_never_completes() {
    let unknown = Ceremony::new()
        .identify(Identity::Unknown)
        .expect("identified");
    assert_eq!(unknown.stage(), Stage::FirstFactor);
    assert_eq!(
        unknown.clone().verified(Method::Password),
        Err(CeremonyRefused::OutOfOrder)
    );
    assert_eq!(unknown.outcome(), None);
}

#[test]
fn a_passkey_that_verified_its_user_is_a_whole_sign_in_and_may_identify() {
    let usernameless = Ceremony::new()
        .passkey_sign_in(user("u1"))
        .expect("signed in");
    assert_eq!(usernameless.stage(), Stage::Complete);
    let (signed_in, assessment) = usernameless.outcome().expect("an outcome");
    assert_eq!(signed_in, &user("u1"));
    assert_eq!(assessment.level, Level::PhishingResistant);

    let identified = Ceremony::new()
        .identify(known("u1", true))
        .expect("identified");
    let done = identified
        .clone()
        .passkey_sign_in(user("u1"))
        .expect("signed in");
    assert_eq!(done.stage(), Stage::Complete, "no second factor after it");
    assert_eq!(
        identified.passkey_sign_in(user("u2")),
        Err(CeremonyRefused::OtherAccount)
    );
    let unknown = Ceremony::new()
        .identify(Identity::Unknown)
        .expect("identified");
    assert_eq!(
        unknown.passkey_sign_in(user("u1")),
        Err(CeremonyRefused::OtherAccount),
        "a passkey cannot take over an identifier that named nobody"
    );
}

#[test]
fn a_passkey_without_user_verification_is_no_first_factor() {
    let identified = Ceremony::new()
        .identify(known("u1", false))
        .expect("identified");
    assert_eq!(
        identified.verified(Method::Passkey {
            user_verified: false
        }),
        Err(CeremonyRefused::MethodNotAccepted)
    );
}
