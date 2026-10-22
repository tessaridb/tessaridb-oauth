//! Groups and memberships as the rest of the server reads them.

use std::collections::BTreeSet;

use tessari_oauth_types::{GroupId, GroupRole, Timestamp, UserId};

/// A group of a company.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Its id.
    pub id: GroupId,
    /// What it is for.
    pub description: String,
    /// The roles its members are released as.
    pub roles: BTreeSet<GroupRole>,
    /// When it was made.
    pub created_at: Timestamp,
}

/// A group to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGroup {
    /// Its id.
    pub id: GroupId,
    /// What it is for, at most `GROUP_DESCRIPTION_MAX_CHARS` characters.
    pub description: String,
    /// The roles its members are released as, at most `GROUP_ROLES_MAX`.
    pub roles: BTreeSet<GroupRole>,
}

/// What making a group did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupCreated {
    /// The group is made.
    Created(Group),
    /// The company already has a group with this id; nothing changed.
    Taken,
}

/// One user in one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// The group.
    pub group: GroupId,
    /// The member.
    pub user: UserId,
    /// When they were added.
    pub added_at: Timestamp,
    /// Who added them.
    pub added_by: String,
}

/// What adding a member did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Joined {
    /// The user is a member, whether or not they were before.
    Added,
    /// The company has no such group; nothing changed.
    NoSuchGroup,
    /// The user is in as many groups as a claim may carry; nothing changed.
    TooManyGroups,
}
