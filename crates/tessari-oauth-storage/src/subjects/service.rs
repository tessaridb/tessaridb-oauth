//! The subject service: the identifier each client knows a user by, under the tenant's pairwise salt.
//!
//! The salt is key material: it is made once per tenant from the system's random source, sealed under the
//! key-encryption key for this tenant and purpose, and never made again — a second salt would give every user a new
//! identifier at every client, orphaning every account a client has linked. Two first requests can both find no salt;
//! the store accepts one of their writes, and the other reads back the salt that won.

use std::ops::Deref;
use std::sync::Arc;

use tessari_oauth_constants::SECRET_CREATE_ATTEMPTS;
use tessari_oauth_core::subject;
use tessari_oauth_infrastructure::custody::{Kek, random_secret};
use tessari_oauth_types::{ClientId, ErrorCategory, TenantId, Timestamp, UserId, base64url};

use super::SecretEntity;
use super::repository::SecretRepository;
use crate::{Error, Result, Tenancy, retry};

/// The record id and sealing binding of the pairwise salt.
const PAIRWISE_SALT: &str = "pairwise";

/// Pairwise subjects.
#[derive(Clone)]
pub struct SubjectService {
    repository: Arc<dyn SecretRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "secret",
        reason: reason.to_owned(),
    }
}

impl SubjectService {
    pub(crate) fn new(repository: Arc<dyn SecretRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// The subject `client` knows `user` of `tenant` by, making the tenant's salt under `kek` at `now` the first time.
    ///
    /// # Errors
    ///
    /// A custody failure when the salt does not open under `kek` for this tenant, and the store's failures.
    pub async fn pairwise(
        &self,
        tenant: &TenantId,
        kek: &Kek,
        client: &ClientId,
        user: &UserId,
        now: Timestamp,
    ) -> Result<String> {
        let salt = self.salt(tenant, kek, now).await?;
        Ok(subject::pairwise(&salt, client, user))
    }

    /// The tenant's salt, cleared from memory when the caller drops it.
    async fn salt(
        &self,
        tenant: &TenantId,
        kek: &Kek,
        now: Timestamp,
    ) -> Result<impl Deref<Target = Vec<u8>> + use<>> {
        let place = self.tenancy.place(tenant)?;
        if let Some(kept) = self.repository.find(&place, PAIRWISE_SALT).await? {
            return open(kek, tenant, &kept);
        }
        let made = SecretEntity {
            sealed: base64url::encode(&kek.seal(tenant, PAIRWISE_SALT, &random_secret()?)?),
            created_at: i64::try_from(now.unix_secs())
                .map_err(|_| unreadable("time beyond i64"))?,
        };
        // A `retry` means a competing first write is still landing; only once it has does a refusal mean it exists.
        let created = retry::bounded(SECRET_CREATE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.create(&place, PAIRWISE_SALT, &made)
        })
        .await;
        match created {
            // Opened from what was written, so the salt in use is the one the store holds.
            Ok(()) => open(kek, tenant, &made),
            // Another request made the salt first; its salt is the tenant's.
            Err(Error::Store(store)) if store.category() == ErrorCategory::Conflict => {
                let kept = self
                    .repository
                    .find(&place, PAIRWISE_SALT)
                    .await?
                    .ok_or_else(|| unreadable("a salt refused as existing and then absent"))?;
                open(kek, tenant, &kept)
            }
            Err(failure) => Err(failure),
        }
    }
}

fn open(
    kek: &Kek,
    tenant: &TenantId,
    kept: &SecretEntity,
) -> Result<impl Deref<Target = Vec<u8>> + use<>> {
    let sealed = base64url::decode(&kept.sealed).map_err(|_| unreadable("sealed"))?;
    Ok(kek.unseal(tenant, PAIRWISE_SALT, &sealed)?)
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
