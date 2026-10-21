//! A consent as the rest of the server reads it: typed values, the revocation with the actor that caused it.

use std::collections::BTreeSet;

use tessari_oauth_core::consents::{ConsentRequest, GrantedConsent};
use tessari_oauth_types::{ClientId, Resource, ScopeSet, TenantId, Timestamp, UserId};

/// Who or what ended a grant. A revocation with no actor cannot be investigated, so there is no such value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revoker {
    /// The user, from their own grant list.
    User,
    /// An operator, during incident response; operators may end a grant but never create one.
    Operator(UserId),
    /// The client was removed, which ends every grant it held.
    ClientRemoved,
}

impl Revoker {
    pub(crate) fn spelled(&self) -> String {
        match self {
            Self::User => "user".to_owned(),
            Self::Operator(operator) => format!("operator:{}", operator.as_str()),
            Self::ClientRemoved => "client-removed".to_owned(),
        }
    }

    pub(crate) fn read(spelled: &str) -> Option<Self> {
        match spelled {
            "user" => Some(Self::User),
            "client-removed" => Some(Self::ClientRemoved),
            other => {
                let operator = other.strip_prefix("operator:")?;
                UserId::parse(operator).ok().map(Self::Operator)
            }
        }
    }
}

/// When a grant ended and who ended it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The instant of the revocation.
    pub at: Timestamp,
    /// Its actor.
    pub by: Revoker,
}

/// What a user has granted one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    /// The tenant the grant lives in.
    pub tenant: TenantId,
    /// The user who granted it.
    pub user: UserId,
    /// The client it was granted to.
    pub client_id: ClientId,
    /// The scopes granted.
    pub scopes: ScopeSet,
    /// The resources the scopes were granted at.
    pub resources: BTreeSet<Resource>,
    /// The consent policy version the user was shown.
    pub policy_version: u32,
    /// The version of the descriptions the user was shown, so a dispute can answer what they were told.
    pub shown_version: String,
    /// When the grant was last given or widened.
    pub granted_at: Timestamp,
    /// The revocation, once there is one.
    pub revoked: Option<Revocation>,
}

impl Consent {
    /// The grant as the coverage check reads it.
    #[must_use]
    pub fn as_granted(&self) -> GrantedConsent {
        GrantedConsent {
            scopes: self.scopes.clone(),
            resources: self.resources.clone(),
            policy_version: self.policy_version,
            revoked: self.revoked.is_some(),
        }
    }
}

/// A grant the user has just given on the consent screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant {
    /// The tenant it is given in.
    pub tenant: TenantId,
    /// The user giving it.
    pub user: UserId,
    /// The client receiving it.
    pub client_id: ClientId,
    /// What the screen asked for and the user accepted.
    pub request: ConsentRequest,
    /// The consent policy version in force.
    pub policy_version: u32,
    /// The version of the descriptions the screen showed.
    pub shown_version: String,
    /// The instant it was given.
    pub at: Timestamp,
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
