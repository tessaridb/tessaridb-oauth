//! The operator service: give a company user a role, take it away, and say which roles they hold now.
//!
//! Two grants are refused here, before anything is written, whoever the caller is: a grant naming its own holder as
//! the giver, because an operator who could raise their own authority would have all of it; and a role above the
//! company's ceiling, which is `companies` anywhere but the `system` company, so a wrong grant cannot exceed what the
//! company's users may hold. A grant carries its giver, reason and expiry, and an expired one is left out of every
//! answer by the read itself. Every grant and every revoke that removed something is appended to the company's audit
//! trail after its write, so the trail is the history of who held what.

use std::sync::Arc;

use tessari_oauth_constants::{OPERATOR_PAGE_MAX, SYSTEM_COMPANY};
use tessari_oauth_types::{TenantId, Timestamp, UserId};

use super::repository::OperatorRepository;
use super::{Granted, OperatorGrant, OperatorGrantEntity, OperatorRole};
use crate::audit::{AuditEvent, AuditKind, AuditService};
use crate::{Error, Result, Tenancy};

/// Operator roles in every company of a region.
pub struct OperatorService {
    repository: Arc<dyn OperatorRepository>,
    tenancy: Tenancy,
    audit: Arc<AuditService>,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "operator grant",
        reason: reason.to_owned(),
    }
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| Error::Invalid {
        record: "operator grant",
        reason: "a time past the store's range",
    })
}

fn instant(stored: i64, field: &str) -> Result<Timestamp> {
    u64::try_from(stored)
        .map(Timestamp::from_unix_secs)
        .map_err(|_| unreadable(field))
}

/// The record id of `role` held by `user`; role names hold no `.`, so the id names one pair.
fn grant_id(user: &UserId, role: OperatorRole) -> String {
    format!("{}.{}", user.as_str(), role.name())
}

fn to_grant(entity: OperatorGrantEntity) -> Result<OperatorGrant> {
    Ok(OperatorGrant {
        user: UserId::parse(entity.user_id).map_err(|_| unreadable("user_id"))?,
        role: OperatorRole::parse(&entity.role_name).ok_or_else(|| unreadable("role_name"))?,
        granted_by: entity.granted_by,
        granted_at: instant(entity.granted_at, "granted_at")?,
        reason: entity.reason,
        expires_at: entity
            .expires_at
            .map(|at| instant(at, "expires_at"))
            .transpose()?,
    })
}

impl OperatorService {
    pub(crate) fn new(
        repository: Arc<dyn OperatorRepository>,
        tenancy: Tenancy,
        audit: Arc<AuditService>,
    ) -> Self {
        Self {
            repository,
            tenancy,
            audit,
        }
    }

    /// Give `grant` in `tenant`, replacing any earlier grant of the same role to the same user.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Invalid`] for a time past the store's range.
    pub async fn grant(&self, tenant: &TenantId, grant: &OperatorGrant) -> Result<Granted> {
        if grant.granted_by == grant.user.as_str() {
            return Ok(Granted::SelfGrant);
        }
        if grant.role == OperatorRole::Companies && tenant.as_str() != SYSTEM_COMPANY {
            return Ok(Granted::AboveCeiling);
        }
        let place = self.tenancy.place(tenant)?;
        let entity = OperatorGrantEntity {
            user_id: grant.user.as_str().to_owned(),
            role_name: grant.role.name().to_owned(),
            granted_by: grant.granted_by.clone(),
            granted_at: seconds(grant.granted_at)?,
            reason: grant.reason.clone(),
            expires_at: grant.expires_at.map(seconds).transpose()?,
        };
        self.repository
            .put(&place, &grant_id(&grant.user, grant.role), &entity)
            .await?;
        let event = AuditEvent {
            user: Some(grant.user.clone()),
            actor: Some(grant.granted_by.clone()),
            role: Some(grant.role),
            reason: Some(grant.reason.clone()),
            ..AuditEvent::of(AuditKind::OperatorGranted)
        };
        self.audit.record(tenant, &event, grant.granted_at).await?;
        Ok(Granted::Granted)
    }

    /// Take `role` from `user` in `tenant`, by `by` for `reason` at `now`; whether the user held it.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a removed record of another shape.
    pub async fn revoke(
        &self,
        tenant: &TenantId,
        user: &UserId,
        role: OperatorRole,
        by: &str,
        reason: &str,
        now: Timestamp,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        if self
            .repository
            .delete(&place, &grant_id(user, role))
            .await?
            .is_none()
        {
            return Ok(false);
        }
        let event = AuditEvent {
            user: Some(user.clone()),
            actor: Some(by.to_owned()),
            role: Some(role),
            reason: Some(reason.to_owned()),
            ..AuditEvent::of(AuditKind::OperatorRevoked)
        };
        self.audit.record(tenant, &event, now).await?;
        Ok(true)
    }

    /// At most `count` grants in `tenant` current at `now` whose role is one of `roles`, after the grant of the role
    /// `after` names, in record order; never more than [`OPERATOR_PAGE_MAX`].
    ///
    /// # Errors
    ///
    /// Store failures, among them the refusal of an anchor the company does not hold, and [`Error::Unreadable`].
    pub async fn page(
        &self,
        tenant: &TenantId,
        roles: &[OperatorRole],
        after: Option<(&UserId, OperatorRole)>,
        count: u32,
        now: Timestamp,
    ) -> Result<Vec<OperatorGrant>> {
        let place = self.tenancy.place(tenant)?;
        let names: Vec<&str> = roles.iter().map(|role| role.name()).collect();
        let anchor = after.map(|(user, role)| grant_id(user, role));
        self.repository
            .page(
                &place,
                &names,
                anchor.as_deref(),
                count.min(OPERATOR_PAGE_MAX),
                seconds(now)?,
            )
            .await?
            .into_iter()
            .map(to_grant)
            .collect()
    }

    /// The grants `user` holds in `tenant` at `now`, expired ones left out.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn grants(
        &self,
        tenant: &TenantId,
        user: &UserId,
        now: Timestamp,
    ) -> Result<Vec<OperatorGrant>> {
        let place = self.tenancy.place(tenant)?;
        // One record per role, so the role count bounds the answer.
        let limit = i64::try_from(OperatorRole::ALL.len()).map_err(|_| unreadable("limit"))?;
        self.repository
            .current(&place, user.as_str(), seconds(now)?, limit)
            .await?
            .into_iter()
            .map(to_grant)
            .collect()
    }
}
