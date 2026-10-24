//! What a sign-in established: the level this issuer publishes as `acr` and the methods it reports as `amr`
//! (RFC 8176), derived only from the methods verified in this interaction: never from what the account has enrolled
//! and never from what a client asked for.
//!
//! The levels, weakest first: one factor category (a password alone, or a passkey that did not verify its user);
//! two different categories (a password with a one-time code); and a passkey that verified its user, which is
//! phishing-resistant because the browser binds it to the origin. A passkey syncs between devices, so its level is
//! not claimed above that.

/// A method verified during one sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A memorised password.
    Password,
    /// A time-based one-time code (RFC 6238).
    Totp,
    /// A single-use recovery code.
    RecoveryCode,
    /// A passkey assertion; `user_verified` when the authenticator verified its user (PIN or biometric).
    Passkey {
        /// Whether the authenticator verified its user.
        user_verified: bool,
    },
}

impl Method {
    /// The name this method is kept by in storage.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Password => "pwd",
            Self::Totp => "totp",
            Self::RecoveryCode => "recovery",
            Self::Passkey {
                user_verified: true,
            } => "passkey-uv",
            Self::Passkey {
                user_verified: false,
            } => "passkey",
        }
    }

    /// The method kept as `name`, when it names one.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Some(match name {
            "pwd" => Self::Password,
            "totp" => Self::Totp,
            "recovery" => Self::RecoveryCode,
            "passkey-uv" => Self::Passkey {
                user_verified: true,
            },
            "passkey" => Self::Passkey {
                user_verified: false,
            },
            _ => return None,
        })
    }
}

/// The level a sign-in reached, as this issuer publishes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// One factor category.
    SingleFactor,
    /// Two different factor categories.
    MultiFactor,
    /// A passkey that verified its user.
    PhishingResistant,
}

impl Level {
    /// The `acr` value naming this level.
    #[must_use]
    pub const fn acr(self) -> &'static str {
        match self {
            Self::SingleFactor => "urn:tessaridb:acr:sf",
            Self::MultiFactor => "urn:tessaridb:acr:mfa",
            Self::PhishingResistant => "urn:tessaridb:acr:phr",
        }
    }
}

/// What a sign-in established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// The level reached.
    pub level: Level,
    /// The `amr` values, each once, in a fixed order.
    pub amr: Vec<&'static str>,
}

/// What `methods`, all verified in one sign-in, establish; none when no method was verified.
#[must_use]
pub fn assess(methods: &[Method]) -> Option<Assessment> {
    if methods.is_empty() {
        return None;
    }
    let password = methods.contains(&Method::Password);
    let one_time = methods
        .iter()
        .any(|method| matches!(method, Method::Totp | Method::RecoveryCode));
    let passkey = methods
        .iter()
        .any(|method| matches!(method, Method::Passkey { .. }));
    let verified_passkey = methods.contains(&Method::Passkey {
        user_verified: true,
    });
    // Something known, something held; a passkey that verified its user is both on its own.
    let categories = [password || verified_passkey, one_time || passkey];
    let multi_factor = categories.iter().all(|present| *present);
    let level = if verified_passkey {
        Level::PhishingResistant
    } else if multi_factor {
        Level::MultiFactor
    } else {
        Level::SingleFactor
    };
    let amr = [
        (password, "pwd"),
        (one_time, "otp"),
        (passkey, "hwk"),
        (multi_factor, "mfa"),
    ]
    .into_iter()
    .filter_map(|(present, value)| present.then_some(value))
    .collect();
    Some(Assessment { level, amr })
}

#[cfg(test)]
#[path = "authentication_tests.rs"]
mod tests;
