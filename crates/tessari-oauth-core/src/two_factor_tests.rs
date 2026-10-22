use super::{TwoFactorPolicy, asks_second_factor, enrolment_due};

#[test]
fn a_policy_is_stored_by_one_name_each_and_nothing_else_reads() {
    for policy in [
        TwoFactorPolicy::Off,
        TwoFactorPolicy::Optional,
        TwoFactorPolicy::Required,
    ] {
        assert_eq!(TwoFactorPolicy::named(policy.name()), Some(policy));
    }
    assert_eq!(TwoFactorPolicy::Optional.name(), "optional");
    assert_eq!(TwoFactorPolicy::named("Required"), None, "one spelling");
    assert_eq!(TwoFactorPolicy::named(""), None);
    assert_eq!(TwoFactorPolicy::default(), TwoFactorPolicy::Optional);
}

#[test]
fn the_sign_in_asks_for_the_app_unless_the_company_turned_two_factor_off() {
    assert!(asks_second_factor(TwoFactorPolicy::Optional, true));
    assert!(asks_second_factor(TwoFactorPolicy::Required, true));
    assert!(!asks_second_factor(TwoFactorPolicy::Off, true));
    for policy in [
        TwoFactorPolicy::Off,
        TwoFactorPolicy::Optional,
        TwoFactorPolicy::Required,
    ] {
        assert!(
            !asks_second_factor(policy, false),
            "{policy:?}: nothing to ask"
        );
    }
}

#[test]
fn enrolment_is_due_only_when_required_and_no_second_factor_is_held() {
    assert!(enrolment_due(TwoFactorPolicy::Required, false));
    assert!(!enrolment_due(TwoFactorPolicy::Required, true));
    assert!(!enrolment_due(TwoFactorPolicy::Optional, false));
    assert!(!enrolment_due(TwoFactorPolicy::Off, false));
}
