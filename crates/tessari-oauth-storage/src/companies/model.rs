//! A company as the server reads it.

use tessari_oauth_types::{TenantId, Timestamp};

/// Whether a company is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompanyStatus {
    /// Created and not yet ready: its database, keys or clients are still being made.
    Provisioning,
    /// Served.
    Active,
    /// Not served: its issuer answers nothing until it is resumed.
    Suspended,
}

impl CompanyStatus {
    /// The stored spelling.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }

    pub(crate) fn parse(stored: &str) -> Option<Self> {
        [Self::Provisioning, Self::Active, Self::Suspended]
            .into_iter()
            .find(|status| status.name() == stored)
    }
}

/// One company of the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Company {
    /// Its tenant id, which is also the last segment of its issuer.
    pub id: TenantId,
    /// The name people see.
    pub name: String,
    /// Whether it is served.
    pub status: CompanyStatus,
    /// When it was created.
    pub created_at: Timestamp,
    /// Who created it: an operator's user id, or `configuration`.
    pub created_by: String,
}

/// What creating a company did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Created {
    /// The company is new, in `provisioning`.
    Created,
    /// A company with that id exists already; nothing was written.
    Taken,
}
