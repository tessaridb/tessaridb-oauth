//! A session as the service hands it out.

use tessari_oauth_core::authentication::Assessment;
use tessari_oauth_types::{Timestamp, UserId};

/// A user's session at this issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The account signed in.
    pub user: UserId,
    /// When it signed in.
    pub auth_time: Timestamp,
    /// What the sign-in established, derived again from the methods it verified.
    pub assessment: Assessment,
}
