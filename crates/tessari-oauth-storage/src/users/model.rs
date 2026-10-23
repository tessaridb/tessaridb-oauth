//! What callers hand the user service and what it answers with.

use tessari_oauth_types::{EmailAddress, UserId};

/// Whether an account may sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    /// It may.
    Active,
    /// An administrator has disabled it.
    Disabled,
}

impl UserStatus {
    /// The stored spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

/// An account found by its sign-in address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAccount {
    /// The account's id.
    pub user: UserId,
    /// The address it signs in with.
    pub email: EmailAddress,
    /// Whether the address has been verified.
    pub email_verified: bool,
    /// Whether it may sign in.
    pub status: UserStatus,
}

/// What a registration did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registered {
    /// A new account, under this id.
    Created(UserId),
    /// The address already belongs to an account; nothing was written.
    AddressTaken,
}

/// A password credential as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPassword {
    /// The hash as a PHC string.
    pub hash: String,
    /// The version of the pepper it was made under.
    pub pepper: u32,
}

/// The names an account's user gave in the account portal (OpenID Connect Core §5.1), each absent until set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// The full name.
    pub name: Option<String>,
    /// The given name.
    pub given_name: Option<String>,
    /// The family name.
    pub family_name: Option<String>,
}
