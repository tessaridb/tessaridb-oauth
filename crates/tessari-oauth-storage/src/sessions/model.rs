//! A session as the service hands it out.

use tessari_oauth_core::authentication::{Assessment, Method};
use tessari_oauth_types::{Timestamp, UserId};

/// A user's session at this issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The account signed in.
    pub user: UserId,
    /// The session's public id, as an ID token's `sid` and logout name it.
    pub sid: String,
    /// When it signed in.
    pub auth_time: Timestamp,
    /// The methods the sign-in verified, in order.
    pub methods: Vec<Method>,
    /// What the sign-in established, derived again from the methods it verified.
    pub assessment: Assessment,
}
