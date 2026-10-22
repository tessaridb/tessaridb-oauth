//! What the factor service answers with.

use zeroize::Zeroizing;

/// What an enrolment did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enrolled {
    /// The factor is stored.
    Created,
    /// The user already has one; nothing was written.
    AlreadyEnrolled,
}

/// A user's one-time code factor, opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpFactor {
    /// The shared secret, cleared from memory when dropped.
    pub secret: Zeroizing<Vec<u8>>,
    /// The last time step a code was accepted for; 0 before the first.
    pub last_step: u64,
}
