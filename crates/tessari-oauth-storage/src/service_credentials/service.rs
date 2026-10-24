//! The service credential service: register a program to call a company's admin API, find it, list them, remove it.
//!
//! A service holds operator roles like a person does, so its roles are bounded here whoever registers it: only
//! `users`, which is what a program managing the company's accounts needs, and never a role that administers the
//! issuer itself. Its key must be an Ed25519 public key, the one algorithm its assertions are verified with. A
//! company holds at most [`SERVICES_MAX`], so the whole set is always one answer.

use std::sync::Arc;

use tessari_oauth_constants::SERVICES_MAX;
use tessari_oauth_core::jose::{Algorithm, VerifyingKey};
use tessari_oauth_types::{ServiceId, TenantId, Timestamp};

use super::repository::ServiceRepository;
use super::{NewService, ServiceCredential, ServiceEntity};
use crate::operators::OperatorRole;
use crate::{Error, Result, Tenancy};

/// The roles a service may hold.
pub const SERVICE_ROLES: [OperatorRole; 1] = [OperatorRole::Users];

/// Registered services in every company of a region.
pub struct ServiceCredentialService {
    repository: Arc<dyn ServiceRepository>,
    tenancy: Tenancy,
}

fn invalid(reason: &'static str) -> Error {
    Error::Invalid {
        record: "service",
        reason,
    }
}

fn unreadable(field: &str) -> Error {
    Error::Unreadable {
        record: "service",
        reason: field.to_owned(),
    }
}

fn to_credential(entity: ServiceEntity) -> Result<ServiceCredential> {
    Ok(ServiceCredential {
        id: ServiceId::parse(entity.service_id).map_err(|_| unreadable("service_id"))?,
        key: VerifyingKey::from_jwk(&entity.public_jwk, Algorithm::EdDsa)
            .map_err(|_| unreadable("public_jwk"))?,
        roles: entity
            .roles
            .iter()
            .map(|name| OperatorRole::parse(name).ok_or_else(|| unreadable("roles")))
            .collect::<Result<_>>()?,
        registered_by: entity.registered_by,
        registered_at: u64::try_from(entity.registered_at)
            .map(Timestamp::from_unix_secs)
            .map_err(|_| unreadable("registered_at"))?,
    })
}

impl ServiceCredentialService {
    pub(crate) fn new(repository: Arc<dyn ServiceRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Register `service` in `tenant` at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a key that is not an Ed25519 public key, no roles or a role a service may not hold, or
    /// a company that already holds [`SERVICES_MAX`]; a store conflict when the id is taken; store failures.
    pub async fn register(
        &self,
        tenant: &TenantId,
        service: &NewService,
        now: Timestamp,
    ) -> Result<ServiceCredential> {
        VerifyingKey::from_jwk(&service.public_jwk, Algorithm::EdDsa)
            .map_err(|_| invalid("the key must be one Ed25519 public key"))?;
        if service.roles.is_empty()
            || !service
                .roles
                .iter()
                .all(|role| SERVICE_ROLES.contains(role))
        {
            return Err(invalid("a service holds the users role and no other"));
        }
        let place = self.tenancy.place(tenant)?;
        let held = self
            .repository
            .list(&place, i64::from(SERVICES_MAX))
            .await?;
        if u32::try_from(held.len()).is_ok_and(|count| count >= SERVICES_MAX) {
            return Err(invalid("the company holds as many services as it may"));
        }
        let entity = ServiceEntity {
            service_id: service.id.as_str().to_owned(),
            public_jwk: service.public_jwk.clone(),
            roles: service
                .roles
                .iter()
                .map(|role| role.name().to_owned())
                .collect(),
            registered_by: service.registered_by.clone(),
            registered_at: i64::try_from(now.unix_secs())
                .map_err(|_| invalid("a time past the store's range"))?,
            reason: service.reason.clone(),
        };
        self.repository.create(&place, &entity).await?;
        to_credential(entity)
    }

    /// The service `id` in `tenant`.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn find(
        &self,
        tenant: &TenantId,
        id: &ServiceId,
    ) -> Result<Option<ServiceCredential>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .find(&place, id.as_str())
            .await?
            .map(to_credential)
            .transpose()
    }

    /// Every service registered in `tenant`, in id order.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn list(&self, tenant: &TenantId) -> Result<Vec<ServiceCredential>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .list(&place, i64::from(SERVICES_MAX))
            .await?
            .into_iter()
            .map(to_credential)
            .collect()
    }

    /// Remove the service `id` from `tenant`; whether there was one.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a removed record of another shape.
    pub async fn remove(&self, tenant: &TenantId, id: &ServiceId) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        Ok(self.repository.delete(&place, id.as_str()).await?.is_some())
    }
}
