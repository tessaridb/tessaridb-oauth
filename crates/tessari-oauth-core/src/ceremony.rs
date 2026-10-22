//! The sign-in ceremony as a state machine: identify, verify a first factor, verify a second one when the account
//! has one enrolled, and only then an outcome. Every step names the stage it belongs to, so a step replayed out of
//! order (a back button, a resent form) is refused rather than moved past.
//!
//! An identifier that names no account still moves the ceremony on, exactly as a known one does, so nothing the
//! browser sees tells the two apart; it simply never reaches an outcome. A passkey that verified its user is a whole
//! sign-in on its own and can also be the step that identifies.

use tessari_oauth_types::UserId;

use crate::authentication::{Assessment, Method, assess};

const VERIFIED_PASSKEY: Method = Method::Passkey {
    user_verified: true,
};

/// Who the ceremony is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// An account, and whether it has a second factor enrolled.
    Known {
        /// The account.
        user: UserId,
        /// Whether a second factor must follow the first.
        second_factor: bool,
    },
    /// An identifier that names no account.
    Unknown,
}

/// Where a ceremony stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Nobody identified yet.
    Identify,
    /// Identified; a first factor is due.
    FirstFactor,
    /// A first factor verified; a second is due.
    SecondFactor,
    /// Signed in.
    Complete,
}

/// Why a step was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CeremonyRefused {
    /// The step does not belong to the stage the ceremony is at.
    #[error("the step does not belong to this stage")]
    OutOfOrder,
    /// The method cannot serve at this stage.
    #[error("the method cannot serve at this stage")]
    MethodNotAccepted,
    /// The passkey belongs to another account than the one identified.
    #[error("the passkey belongs to another account")]
    OtherAccount,
}

/// One sign-in in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceremony {
    identity: Option<Identity>,
    verified: Vec<Method>,
}

impl Ceremony {
    /// A ceremony nobody has started.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            identity: None,
            verified: Vec::new(),
        }
    }

    /// The ceremony that `identity` and `verified`, as kept between requests, describe, rebuilt through the same
    /// steps, so kept parts no step could have produced are refused.
    ///
    /// # Errors
    ///
    /// The refusal of the first step the parts could not have taken.
    pub fn resume(
        identity: Option<Identity>,
        verified: Vec<Method>,
    ) -> Result<Self, CeremonyRefused> {
        let started = match identity {
            Some(identity) => Self::new().identify(identity)?,
            None => Self::new(),
        };
        verified
            .into_iter()
            .try_fold(started, |ceremony, method| ceremony.verified(method))
    }

    /// Who the ceremony is about, once identified.
    #[must_use]
    pub const fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// The methods verified so far, in order.
    #[must_use]
    pub fn verified_methods(&self) -> &[Method] {
        &self.verified
    }

    /// The stage this ceremony is at.
    #[must_use]
    pub fn stage(&self) -> Stage {
        match &self.identity {
            None => Stage::Identify,
            Some(Identity::Unknown) => Stage::FirstFactor,
            Some(Identity::Known { second_factor, .. }) => {
                let whole = self.verified.contains(&VERIFIED_PASSKEY);
                match self.verified.len() {
                    0 => Stage::FirstFactor,
                    1 if *second_factor && !whole => Stage::SecondFactor,
                    _ => Stage::Complete,
                }
            }
        }
    }

    /// Identify the account the sign-in is for.
    ///
    /// # Errors
    ///
    /// [`CeremonyRefused::OutOfOrder`] once somebody is identified.
    pub fn identify(self, identity: Identity) -> Result<Self, CeremonyRefused> {
        if self.identity.is_some() {
            return Err(CeremonyRefused::OutOfOrder);
        }
        Ok(Self {
            identity: Some(identity),
            ..self
        })
    }

    /// Record a first or second factor verified for the identified account.
    ///
    /// # Errors
    ///
    /// [`CeremonyRefused::OutOfOrder`] before identification, for an account that does not exist and after the
    /// outcome; [`CeremonyRefused::MethodNotAccepted`] for a method that cannot serve at this stage.
    pub fn verified(mut self, method: Method) -> Result<Self, CeremonyRefused> {
        let accepted = match self.stage() {
            Stage::Identify | Stage::Complete => return Err(CeremonyRefused::OutOfOrder),
            Stage::FirstFactor if self.identity == Some(Identity::Unknown) => {
                return Err(CeremonyRefused::OutOfOrder);
            }
            Stage::FirstFactor => matches!(method, Method::Password | VERIFIED_PASSKEY),
            Stage::SecondFactor => !matches!(method, Method::Password),
        };
        if !accepted {
            return Err(CeremonyRefused::MethodNotAccepted);
        }
        self.verified.push(method);
        Ok(self)
    }

    /// Record a passkey that verified its user as the whole sign-in of `user`, identifying it when nobody is yet.
    ///
    /// # Errors
    ///
    /// [`CeremonyRefused::OtherAccount`] when another account was identified; [`CeremonyRefused::OutOfOrder`] after
    /// a first factor.
    pub fn passkey_sign_in(self, user: UserId) -> Result<Self, CeremonyRefused> {
        match (self.stage(), &self.identity) {
            (Stage::Identify, _) => self.identify(Identity::Known {
                user,
                second_factor: false,
            })?,
            (
                Stage::FirstFactor,
                Some(Identity::Known {
                    user: identified, ..
                }),
            ) if *identified == user => self,
            (Stage::FirstFactor, _) => return Err(CeremonyRefused::OtherAccount),
            (Stage::SecondFactor | Stage::Complete, _) => return Err(CeremonyRefused::OutOfOrder),
        }
        .verified(VERIFIED_PASSKEY)
    }

    /// The account signed in and what the sign-in established, once complete.
    #[must_use]
    pub fn outcome(&self) -> Option<(&UserId, Assessment)> {
        match (&self.identity, self.stage()) {
            (Some(Identity::Known { user, .. }), Stage::Complete) => {
                assess(&self.verified).map(|assessment| (user, assessment))
            }
            _ => None,
        }
    }
}

impl Default for Ceremony {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "ceremony_tests.rs"]
mod tests;
