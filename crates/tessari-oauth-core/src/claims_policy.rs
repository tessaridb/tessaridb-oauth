//! The claims policy: the one table naming every claim this server releases beyond the authentication facts, the scope
//! that releases it, where it may appear and where its value comes from (OpenID Connect Core §5.4; release only what a
//! granted scope names). A claim missing from the table is never released, and the table is read at request time
//! from current data, so a membership removed a moment ago is gone from the next answer.

use std::collections::BTreeSet;

use tessari_oauth_constants::GROUPS_SCOPE;
use tessari_oauth_types::{GroupId, GroupRole};

/// Where a released claim may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The UserInfo answer only: never the ID token, which travels through the browser, and never the access token,
    /// which every resource it is addressed to reads.
    UserInfo,
}

/// One row of the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// The claim's name in the answer.
    pub claim: &'static str,
    /// The scope that releases it.
    pub scope: &'static str,
    /// Where it may appear.
    pub place: Place,
    /// Where its value comes from.
    pub source: &'static str,
}

/// Every claim released beyond the authentication facts.
pub const POLICY: [Rule; 2] = [
    Rule {
        claim: "groups",
        scope: GROUPS_SCOPE,
        place: Place::UserInfo,
        source: "the ids of the company's groups the user is in",
    },
    Rule {
        claim: "roles",
        scope: GROUPS_SCOPE,
        place: Place::UserInfo,
        source: "the roles those groups carry",
    },
];

/// Whether `claim` is released at `place` to a token carrying `scopes`.
#[must_use]
pub fn releases(claim: &str, place: Place, scopes: &[String]) -> bool {
    POLICY.iter().any(|rule| {
        rule.claim == claim && rule.place == place && scopes.iter().any(|scope| scope == rule.scope)
    })
}

/// The `groups` and `roles` claims of a user in `groups`: the group ids in order, and every role they carry, each
/// once and in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupClaims {
    /// The ids of the groups.
    pub groups: Vec<String>,
    /// The roles they carry.
    pub roles: Vec<String>,
}

/// The group claims of a user in `groups`.
#[must_use]
pub fn group_claims<'a>(
    groups: impl IntoIterator<Item = (&'a GroupId, &'a BTreeSet<GroupRole>)>,
) -> GroupClaims {
    let mut ids = BTreeSet::new();
    let mut roles = BTreeSet::new();
    for (id, carried) in groups {
        ids.insert(id.as_str());
        roles.extend(carried.iter().map(GroupRole::as_str));
    }
    GroupClaims {
        groups: ids.into_iter().map(str::to_owned).collect(),
        roles: roles.into_iter().map(str::to_owned).collect(),
    }
}

#[cfg(test)]
#[path = "claims_policy_tests.rs"]
mod tests;
