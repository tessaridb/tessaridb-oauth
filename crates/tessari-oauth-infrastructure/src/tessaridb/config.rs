//! How to reach the store, read from the environment at start-up and never logged in full.

use std::fmt;

/// The store's wire address and the account the server signs in with.
#[derive(Clone, PartialEq, Eq)]
pub struct StoreConfig {
    /// The node's wire `host:port`.
    pub address: String,
    /// The account name.
    pub user: String,
    /// The account's password; spent once per connection and never printed.
    pub password: String,
    /// The certificate (PEM) the node's chain must lead to. Without one the store is reached in the clear, which
    /// is accepted only to a loopback IP literal.
    pub authority: Option<Vec<u8>>,
}

impl fmt::Debug for StoreConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoreConfig")
            .field("address", &self.address)
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .field("authority", &self.authority.as_ref().map(|_| "<set>"))
            .finish()
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
