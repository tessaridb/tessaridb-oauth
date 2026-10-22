//! The admin console's records as the service hands them out.

use tessari_oauth_core::authentication::{Assessment, Method};
use tessari_oauth_types::{SessionSecret, Timestamp, UserId};

/// A sign-in to the admin console in progress, taken back once by the browser that began it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSignin {
    pub(crate) state: String,
    /// The PKCE verifier the code is redeemed with.
    pub verifier: String,
    /// The `nonce` the code must carry back.
    pub nonce: String,
}

impl PendingSignin {
    /// Whether `presented` is the `state` this sign-in sent.
    #[must_use]
    pub fn state_matches(&self, presented: &str) -> bool {
        // Digests are compared, never the values: a timing difference over a SHA-256 output says nothing about the
        // value it was taken of, and a stored row never holds the value itself.
        SessionSecret::from_secret(presented).digest() == self.state
    }
}

/// An operator's session in the admin console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSession {
    /// The operator signed in.
    pub user: UserId,
    /// The public id of the issuer session it came from; the console session ends with that one.
    pub sid: String,
    /// When the operator signed in.
    pub auth_time: Timestamp,
    /// The methods the sign-in verified, in order.
    pub methods: Vec<Method>,
    /// What the sign-in established, derived again from the methods it verified.
    pub assessment: Assessment,
}
