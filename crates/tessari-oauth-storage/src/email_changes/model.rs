//! What the address-change service answers in.

use tessari_oauth_types::{EmailAddress, Timestamp, UserId};

/// A change the new address has just confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedChange {
    /// The account whose address changes.
    pub user: UserId,
    /// The address it changes to.
    pub new_address: EmailAddress,
    /// When the change takes effect, unless the old address cancels it first.
    pub effective_at: Timestamp,
}

/// A confirmed change whose hold is over, waiting to be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueChange {
    /// The change's record id.
    pub id: String,
    /// The account whose address changes.
    pub user: UserId,
    /// The address the account signs in with now.
    pub old_address: EmailAddress,
    /// The address it changes to.
    pub new_address: EmailAddress,
    /// When the new address confirmed it, in Unix seconds: the moment that address was proved.
    pub confirmed_at: i64,
}
