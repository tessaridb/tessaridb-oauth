//! Whether a request is inside what the user already granted this client, and if not, what must be put to them.
//!
//! A grant covers a request only when every scope and every resource asked for is in it, under the consent policy
//! in force now. Anything else is a prompt showing the DELTA, so an escalation is seen rather than buried; no
//! record, a revoked record and a record given under an older policy all prompt for the whole request, because the
//! user never agreed to it in the terms the server would now be relying on.

use std::collections::BTreeSet;

use tessari_oauth_types::{Resource, ScopeSet};

/// What the user granted a client, as far as coverage needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedConsent {
    /// The scopes granted.
    pub scopes: ScopeSet,
    /// The resources the scopes were granted at.
    pub resources: BTreeSet<Resource>,
    /// The consent policy version the user was shown.
    pub policy_version: u32,
    /// Whether the grant has been revoked.
    pub revoked: bool,
}

/// What a request asks the user to grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRequest {
    /// The scopes requested.
    pub scopes: ScopeSet,
    /// The resources requested.
    pub resources: BTreeSet<Resource>,
}

/// The answer: covered, or what the prompt must show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    /// Every scope and resource is inside the grant, under the current policy.
    Covered,
    /// The user must be asked; these are the scopes and resources not already granted.
    Prompt {
        /// Scopes outside the grant, if any.
        scopes: Option<ScopeSet>,
        /// Resources outside the grant.
        resources: BTreeSet<Resource>,
    },
}

/// Whether `request` is covered by `granted` under `policy_version`, or the delta to prompt for.
#[must_use]
pub fn coverage(
    granted: Option<&GrantedConsent>,
    request: &ConsentRequest,
    policy_version: u32,
) -> Coverage {
    let Some(granted) =
        granted.filter(|grant| !grant.revoked && grant.policy_version == policy_version)
    else {
        return Coverage::Prompt {
            scopes: Some(request.scopes.clone()),
            resources: request.resources.clone(),
        };
    };
    let scopes = request.scopes.missing_from(&granted.scopes);
    let resources: BTreeSet<Resource> = request
        .resources
        .difference(&granted.resources)
        .cloned()
        .collect();
    if scopes.is_none() && resources.is_empty() {
        Coverage::Covered
    } else {
        Coverage::Prompt { scopes, resources }
    }
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod tests;
