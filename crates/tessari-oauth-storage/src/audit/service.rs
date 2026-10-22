//! The audit service: append a message for what happened, and read the trail back in order.
//!
//! Every message is named by a fresh random id, so an append that is retried is refused as a duplicate rather than
//! landing twice; its position is the store's, dense and in commit order, so a gap in a reader's sequence is a loss
//! that can be counted.

use std::sync::Arc;

use tessari_oauth_infrastructure::custody::token_id;
use tessari_oauth_infrastructure::tessaridb::{FromRecord, Row};
use tessari_oauth_types::{ClientId, KeyThumbprint, ScopeSet, TenantId, Timestamp, UserId};

use super::entity::AuditMessageEntity;
use super::repository::AuditRepository;
use super::{AuditEntity, AuditEvent, AuditKind, AuditRecord};
use crate::operators::OperatorRole;
use crate::{Error, Result, Tenancy};

/// The audit trail.
#[derive(Clone)]
pub struct AuditService {
    repository: Arc<dyn AuditRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "audit message",
        reason: reason.to_owned(),
    }
}

fn to_entity(event: &AuditEvent, now: Timestamp) -> Result<AuditEntity> {
    Ok(AuditEntity {
        kind: event.kind.as_str().to_owned(),
        client_id: event.client_id.as_ref().map(|id| id.as_str().to_owned()),
        user_id: event.user.as_ref().map(|id| id.as_str().to_owned()),
        subject: event.subject.clone(),
        scopes: event
            .scopes
            .as_ref()
            .map(|scopes| scopes.iter().map(str::to_owned).collect()),
        audience: event.audience.clone(),
        jti: event.jti.clone(),
        auth_method: event.auth_method.clone(),
        jkt: event
            .bound_to
            .as_ref()
            .map(|thumbprint| thumbprint.as_str().to_owned()),
        reason: event.reason.clone(),
        families: event
            .families
            .map(i64::try_from)
            .transpose()
            .map_err(|_| Error::Invalid {
                record: "audit message",
                reason: "a count beyond i64",
            })?,
        actor: event.actor.clone(),
        role_name: event.role.map(|role| role.name().to_owned()),
        at: i64::try_from(now.unix_secs()).map_err(|_| Error::Invalid {
            record: "audit message",
            reason: "a time beyond i64",
        })?,
    })
}

fn to_record(message: AuditMessageEntity) -> Result<AuditRecord> {
    let row =
        Row::new(message.id, message.value).map_err(|fault| unreadable(&fault.to_string()))?;
    let entity = AuditEntity::from_row(row).map_err(|fault| unreadable(&fault.to_string()))?;
    let event = AuditEvent {
        kind: AuditKind::parse(&entity.kind).ok_or_else(|| unreadable("kind"))?,
        client_id: entity
            .client_id
            .map(ClientId::parse)
            .transpose()
            .map_err(|_| unreadable("client_id"))?,
        user: entity
            .user_id
            .map(UserId::parse)
            .transpose()
            .map_err(|_| unreadable("user_id"))?,
        subject: entity.subject,
        scopes: entity
            .scopes
            .map(|scopes| ScopeSet::parse(&scopes.join(" ")))
            .transpose()
            .map_err(|_| unreadable("scopes"))?,
        audience: entity.audience,
        jti: entity.jti,
        auth_method: entity.auth_method,
        bound_to: entity
            .jkt
            .map(KeyThumbprint::parse)
            .transpose()
            .map_err(|_| unreadable("jkt"))?,
        reason: entity.reason,
        families: entity
            .families
            .map(u64::try_from)
            .transpose()
            .map_err(|_| unreadable("families"))?,
        actor: entity.actor,
        role: entity
            .role_name
            .map(|name| OperatorRole::parse(&name).ok_or_else(|| unreadable("role_name")))
            .transpose()?,
    };
    Ok(AuditRecord {
        position: u64::try_from(message.position).map_err(|_| unreadable("position"))?,
        at: Timestamp::from_unix_secs(u64::try_from(entity.at).map_err(|_| unreadable("at"))?),
        event,
    })
}

impl AuditService {
    pub(crate) fn new(repository: Arc<dyn AuditRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Append `event` to `tenant`'s trail at `now`.
    ///
    /// # Errors
    ///
    /// When the system's random source fails, or the store is unavailable or refuses.
    pub async fn record(
        &self,
        tenant: &TenantId,
        event: &AuditEvent,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let id = token_id()?;
        self.repository
            .append(&place, &id, &to_entity(event, now)?)
            .await
    }

    /// At most `limit` messages of `tenant`'s trail after position `after`, in order.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses, or holds a message this crate cannot read.
    pub async fn read_after(
        &self,
        tenant: &TenantId,
        after: u64,
        limit: u64,
    ) -> Result<Vec<AuditRecord>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .read_after(&place, after, limit)
            .await?
            .into_iter()
            .map(to_record)
            .collect()
    }
}
