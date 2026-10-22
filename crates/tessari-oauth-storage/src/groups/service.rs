//! The group service: make and delete a company's groups, set the roles each carries, and put users in and out of
//! them. Every read and write is inside the company's own database, so another company's group is not addressable at
//! all. A group holds users and never another group. A user is in at most `GROUPS_PER_USER_MAX` groups, so every group
//! they are in fits the one claim that releases them.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_constants::{
    GROUP_DESCRIPTION_MAX_CHARS, GROUP_PAGE_MAX, GROUP_ROLES_MAX, GROUPS_PER_USER_MAX,
};
use tessari_oauth_types::{ErrorCategory, GroupId, GroupRole, TenantId, Timestamp, UserId};

use super::repository::GroupRepository;
use super::{Group, GroupCreated, GroupEntity, Joined, Membership, MembershipEntity, NewGroup};
use crate::{Error, Result, Tenancy};

/// The groups of every company of a region.
pub struct GroupService {
    repository: Arc<dyn GroupRepository>,
    tenancy: Tenancy,
}

fn unreadable(record: &'static str, reason: &str) -> Error {
    Error::Unreadable {
        record,
        reason: reason.to_owned(),
    }
}

fn invalid(reason: &'static str) -> Error {
    Error::Invalid {
        record: "group",
        reason,
    }
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| invalid("a time past the store's range"))
}

fn instant(stored: i64, record: &'static str) -> Result<Timestamp> {
    u64::try_from(stored)
        .map(Timestamp::from_unix_secs)
        .map_err(|_| unreadable(record, "a time before 1970"))
}

/// The record id of `user` in `group`; neither id holds a `.`, so the id names one pair.
fn membership_id(group: &GroupId, user: &UserId) -> String {
    format!("{}.{}", group.as_str(), user.as_str())
}

/// Whether `failure` is the store refusing a write its condition or an existing record stopped, rather than a write
/// that may succeed if sent again.
fn refused_by_state(failure: &Error) -> bool {
    matches!(failure, Error::Store(store) if store.category() == ErrorCategory::Conflict && !store.is_retry())
}

fn to_group(entity: GroupEntity) -> Result<Group> {
    Ok(Group {
        id: GroupId::parse(entity.group_id).map_err(|_| unreadable("group", "group_id"))?,
        description: entity.description,
        roles: entity
            .roles
            .into_iter()
            .map(|role| GroupRole::parse(role).map_err(|_| unreadable("group", "roles")))
            .collect::<Result<BTreeSet<_>>>()?,
        created_at: instant(entity.created_at, "group")?,
    })
}

fn to_membership(entity: MembershipEntity) -> Result<Membership> {
    Ok(Membership {
        group: GroupId::parse(entity.group_id)
            .map_err(|_| unreadable("group membership", "group_id"))?,
        user: UserId::parse(entity.user_id)
            .map_err(|_| unreadable("group membership", "user_id"))?,
        added_at: instant(entity.added_at, "group membership")?,
        added_by: entity.added_by,
    })
}

fn role_names(roles: &BTreeSet<GroupRole>) -> Result<Vec<String>> {
    if roles.len() > GROUP_ROLES_MAX {
        return Err(invalid("more roles than a group carries"));
    }
    Ok(roles.iter().map(|role| role.as_str().to_owned()).collect())
}

impl GroupService {
    pub(crate) fn new(repository: Arc<dyn GroupRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Make `group` in `tenant` at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a description or role set past its bound, and the store's failures.
    pub async fn create(
        &self,
        tenant: &TenantId,
        group: &NewGroup,
        now: Timestamp,
    ) -> Result<GroupCreated> {
        if group.description.chars().count() > GROUP_DESCRIPTION_MAX_CHARS {
            return Err(invalid("a description longer than a group's"));
        }
        let place = self.tenancy.place(tenant)?;
        let entity = GroupEntity {
            group_id: group.id.as_str().to_owned(),
            tenant: tenant.as_str().to_owned(),
            description: group.description.clone(),
            roles: role_names(&group.roles)?,
            created_at: seconds(now)?,
        };
        match self.repository.create(&place, &entity).await {
            Ok(()) => Ok(GroupCreated::Created(to_group(entity)?)),
            Err(failure) if refused_by_state(&failure) => Ok(GroupCreated::Taken),
            Err(failure) => Err(failure),
        }
    }

    /// The group `group` of `tenant`, if it has one.
    ///
    /// # Errors
    ///
    /// The store's failures, and [`Error::Unreadable`] for a record of another shape.
    pub async fn find(&self, tenant: &TenantId, group: &GroupId) -> Result<Option<Group>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .find(&place, group.as_str())
            .await?
            .map(to_group)
            .transpose()
    }

    /// At most `count` (1 to `GROUP_PAGE_MAX`) groups of `tenant` after `after`, in id order.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a count outside its bounds, and the store's failures.
    pub async fn page(
        &self,
        tenant: &TenantId,
        after: Option<&GroupId>,
        count: u32,
    ) -> Result<Vec<Group>> {
        if !(1..=GROUP_PAGE_MAX).contains(&count) {
            return Err(invalid("a page size outside its bounds"));
        }
        let place = self.tenancy.place(tenant)?;
        self.repository
            .page(&place, after.map(GroupId::as_str), count)
            .await?
            .into_iter()
            .map(to_group)
            .collect()
    }

    /// Set the roles `group` of `tenant` carries; whether the group was there.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a role set past its bound, and the store's failures.
    pub async fn set_roles(
        &self,
        tenant: &TenantId,
        group: &GroupId,
        roles: &BTreeSet<GroupRole>,
    ) -> Result<bool> {
        let names = role_names(roles)?;
        let place = self.tenancy.place(tenant)?;
        match self
            .repository
            .set_roles(&place, group.as_str(), &names)
            .await
        {
            Ok(()) => Ok(true),
            Err(failure) if refused_by_state(&failure) => Ok(false),
            Err(failure) => Err(failure),
        }
    }

    /// Delete `group` of `tenant` and every membership of it; whether the group was there.
    ///
    /// # Errors
    ///
    /// The store's failures.
    pub async fn delete(&self, tenant: &TenantId, group: &GroupId) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        if self
            .repository
            .find(&place, group.as_str())
            .await?
            .is_none()
        {
            return Ok(false);
        }
        self.repository.delete(&place, group.as_str()).await?;
        Ok(true)
    }

    /// Put `user` in `group` of `tenant`, by `by` at `now`.
    ///
    /// # Errors
    ///
    /// The store's failures.
    pub async fn join(
        &self,
        tenant: &TenantId,
        group: &GroupId,
        user: &UserId,
        by: &str,
        now: Timestamp,
    ) -> Result<Joined> {
        let place = self.tenancy.place(tenant)?;
        let held = self
            .repository
            .memberships(&place, user.as_str(), GROUPS_PER_USER_MAX)
            .await?;
        let already = held.iter().any(|entity| entity.group_id == group.as_str());
        let full = u32::try_from(held.len()).map_or(true, |count| count >= GROUPS_PER_USER_MAX);
        if full && !already {
            return Ok(Joined::TooManyGroups);
        }
        let entity = MembershipEntity {
            group_id: group.as_str().to_owned(),
            user_id: user.as_str().to_owned(),
            added_at: seconds(now)?,
            added_by: by.to_owned(),
        };
        match self.repository.join(&place, &entity).await {
            Ok(()) => Ok(Joined::Added),
            Err(failure) if refused_by_state(&failure) => Ok(Joined::NoSuchGroup),
            Err(failure) => Err(failure),
        }
    }

    /// Take `user` out of `group` of `tenant`; whether they were in it.
    ///
    /// # Errors
    ///
    /// The store's failures.
    pub async fn leave(&self, tenant: &TenantId, group: &GroupId, user: &UserId) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .leave(&place, &membership_id(group, user))
            .await
    }

    /// At most `count` (1 to `GROUP_PAGE_MAX`) members of `group` of `tenant` after `after`, in id order.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a count outside its bounds, and the store's failures.
    pub async fn members(
        &self,
        tenant: &TenantId,
        group: &GroupId,
        after: Option<&UserId>,
        count: u32,
    ) -> Result<Vec<Membership>> {
        if !(1..=GROUP_PAGE_MAX).contains(&count) {
            return Err(invalid("a page size outside its bounds"));
        }
        let place = self.tenancy.place(tenant)?;
        let after = after.map(|user| membership_id(group, user));
        self.repository
            .members(&place, group.as_str(), after.as_deref(), count)
            .await?
            .into_iter()
            .map(to_membership)
            .collect()
    }

    /// Every group of `tenant` that `user` is in, in id order.
    ///
    /// # Errors
    ///
    /// The store's failures, and [`Error::Unreadable`] for a record of another shape.
    pub async fn groups_of(&self, tenant: &TenantId, user: &UserId) -> Result<Vec<Group>> {
        let place = self.tenancy.place(tenant)?;
        let held = self
            .repository
            .memberships(&place, user.as_str(), GROUPS_PER_USER_MAX)
            .await?;
        if held.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<String> = held.into_iter().map(|entity| entity.group_id).collect();
        // A membership is never left without its group, but a group deleted between the two reads is simply gone.
        let mut groups = self
            .repository
            .find_many(&place, &ids)
            .await?
            .into_iter()
            .map(to_group)
            .collect::<Result<Vec<_>>>()?;
        groups.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(groups)
    }
}
