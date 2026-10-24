//! Operator roles as the server reads them.

use tessari_oauth_types::{Timestamp, UserId};

/// One task an operator may perform in their company. A person may hold several; none of them grants everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorRole {
    /// Create, suspend and resume companies; held only in the `system` company.
    Companies,
    /// Create, enrol and disable the company's users.
    Users,
    /// Register and change the company's clients.
    Clients,
    /// Change the company's sign-in policy.
    Policy,
    /// Read the company's signing keys, make a successor early and withdraw a compromised one.
    Keys,
    /// Read the company's audit trail.
    Audit,
}

impl OperatorRole {
    /// Every role.
    pub const ALL: [Self; 6] = [
        Self::Companies,
        Self::Users,
        Self::Clients,
        Self::Policy,
        Self::Keys,
        Self::Audit,
    ];

    /// The stored and spoken name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Companies => "companies",
            Self::Users => "users",
            Self::Clients => "clients",
            Self::Policy => "policy",
            Self::Keys => "keys",
            Self::Audit => "audit",
        }
    }

    /// The role `name` names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.name() == name)
    }
}

/// One role held by one user of a company, and the record of who gave it and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorGrant {
    /// Who holds it.
    pub user: UserId,
    /// What it lets them do.
    pub role: OperatorRole,
    /// Who gave it: an operator's user id, or `break-glass`.
    pub granted_by: String,
    /// When it was given.
    pub granted_at: Timestamp,
    /// Why it was given.
    pub reason: String,
    /// When it stops counting; never, when absent.
    pub expires_at: Option<Timestamp>,
}

/// What granting a role did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granted {
    /// The user holds the role, with this grant's reason and expiry.
    Granted,
    /// The grant named its own holder as the giver; nothing was written.
    SelfGrant,
    /// The role is not one this company's users may hold; nothing was written.
    AboveCeiling,
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
