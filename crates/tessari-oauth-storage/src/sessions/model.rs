//! A session as the service hands it out.

use tessari_oauth_core::authentication::{Assessment, Method};
use tessari_oauth_types::{ClientId, Timestamp, UserId};

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
    /// The clients it was signed in to with an ID token, each once.
    pub clients: Vec<ClientId>,
}

/// A live session as its user's own list shows it: its public id and what is known about it, never its cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedSession {
    /// The session's public id.
    pub sid: String,
    /// When it signed in.
    pub auth_time: Timestamp,
    /// When a request last found it.
    pub seen_at: Timestamp,
    /// The methods the sign-in verified, in order.
    pub methods: Vec<Method>,
}
