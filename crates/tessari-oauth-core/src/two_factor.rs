//! A company's two-factor policy, and what it decides. `off`: the sign-in asks no second factor and none is offered;
//! `optional`: each user chooses, and a user who holds an authenticator app is asked for its code; `required`: the
//! same, and a user holding no second factor must enrol one before the session serves anything but that.

/// A company's two-factor policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TwoFactorPolicy {
    /// No second factor is asked for or offered.
    Off,
    /// Each user chooses.
    #[default]
    Optional,
    /// Every user holds one.
    Required,
}

impl TwoFactorPolicy {
    /// The name the policy is stored under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }

    /// The policy stored under `name`, in its one spelling.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "off" => Some(Self::Off),
            "optional" => Some(Self::Optional),
            "required" => Some(Self::Required),
            _ => None,
        }
    }
}

/// Whether a sign-in under `policy` asks for a second factor from an account that `holds_app` or not.
#[must_use]
pub const fn asks_second_factor(policy: TwoFactorPolicy, holds_app: bool) -> bool {
    holds_app && !matches!(policy, TwoFactorPolicy::Off)
}

/// Whether an account that `holds_second_factor` or not must enrol one under `policy` before its session serves
/// anything else.
#[must_use]
pub const fn enrolment_due(policy: TwoFactorPolicy, holds_second_factor: bool) -> bool {
    !holds_second_factor && matches!(policy, TwoFactorPolicy::Required)
}

#[cfg(test)]
#[path = "two_factor_tests.rs"]
mod tests;
