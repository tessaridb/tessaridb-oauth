//! The key service: a tenant's signing keys, kept sealed; what to do with them is the rotation rule's decision.

use std::sync::Arc;

use tessari_oauth_core::keys::{self, KeyRecord};
use tessari_oauth_infrastructure::custody::{Kek, SigningKey};
use tessari_oauth_types::{Algorithm, KeyThumbprint, TenantId, Timestamp, base64url};

use super::repository::KeyRepository;
use super::{KeyEntity, StoredKey};
use crate::{Error, Result, Tenancy};

/// A tenant's signing keys.
#[derive(Clone)]
pub struct KeyService {
    repository: Arc<dyn KeyRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "signing key",
        reason: reason.to_owned(),
    }
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| unreadable("time beyond i64"))
}

fn algorithm(name: &str) -> Result<Algorithm> {
    [Algorithm::EdDsa, Algorithm::Es256]
        .into_iter()
        .find(|algorithm| algorithm.name() == name)
        .ok_or_else(|| unreadable("algorithm"))
}

fn to_model(row: KeyEntity) -> Result<StoredKey> {
    let created = u64::try_from(row.created_at).map_err(|_| unreadable("negative time"))?;
    Ok(StoredKey {
        kid: KeyThumbprint::parse(row.kid).map_err(|_| unreadable("kid"))?,
        algorithm: algorithm(&row.algorithm)?,
        sealed: base64url::decode(&row.sealed).map_err(|_| unreadable("sealed"))?,
        public_jwk: row.public_jwk,
        created_at: Timestamp::from_unix_secs(created),
        compromised: row.compromised,
    })
}

impl KeyService {
    pub(crate) fn new(repository: Arc<dyn KeyRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Record a new key for `tenant`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses — including a `kid` that already exists, so a `kid` is never reused.
    pub async fn add(&self, tenant: &TenantId, key: &StoredKey) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let row = KeyEntity {
            kid: key.kid.as_str().to_owned(),
            tenant: tenant.as_str().to_owned(),
            algorithm: key.algorithm.name().to_owned(),
            sealed: base64url::encode(&key.sealed),
            public_jwk: key.public_jwk.clone(),
            created_at: seconds(key.created_at)?,
            compromised: key.compromised,
            retired_at: None,
        };
        self.repository.create(&place, &row).await
    }

    /// Every key of `tenant` not yet retired, oldest first — the input of the rotation rule.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or holds a row this crate cannot read.
    pub async fn live(&self, tenant: &TenantId) -> Result<Vec<StoredKey>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .live(&place)
            .await?
            .into_iter()
            .map(to_model)
            .collect()
    }

    /// The key `tenant` signs with at `now`, as the rotation rule chooses it, opened under `kek`.
    ///
    /// # Errors
    ///
    /// [`Error::NoSigningKey`] when the rule has no key to sign with; a custody failure when the key does not open for
    /// this tenant and `kid`; and the store's failures.
    pub async fn signer(&self, tenant: &TenantId, kek: &Kek, now: Timestamp) -> Result<SigningKey> {
        let live = self.live(tenant).await?;
        let records: Vec<KeyRecord> = live
            .iter()
            .map(|key| KeyRecord {
                kid: key.kid.clone(),
                created_at: key.created_at,
                compromised: key.compromised,
            })
            .collect();
        let kid = keys::plan(&records, now)
            .signing
            .ok_or(Error::NoSigningKey)?;
        let key = live
            .into_iter()
            .find(|key| key.kid == kid)
            .ok_or(Error::NoSigningKey)?;
        let pkcs8 = kek.unseal(tenant, kid.as_str(), &key.sealed)?;
        Ok(SigningKey::from_pkcs8(key.algorithm, &pkcs8)?)
    }

    /// Retire `kid` of `tenant` at `at`; it is no longer published.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses.
    pub async fn retire(
        &self,
        tenant: &TenantId,
        kid: &KeyThumbprint,
        at: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .retire(&place, kid.as_str(), seconds(at)?)
            .await
    }

    /// Withdraw `kid` of `tenant` at once; the rotation rule stops publishing and signing with it.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses.
    pub async fn compromise(&self, tenant: &TenantId, kid: &KeyThumbprint) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        self.repository.compromise(&place, kid.as_str()).await
    }
}
