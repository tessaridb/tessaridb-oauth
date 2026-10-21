//! The consent service: write a grant, answer whether a request is covered, list a user's grants, revoke one.
//!
//! One record per user and client. A grant under the policy already recorded WIDENS the record — what the user
//! granted before stays granted — and a grant under a newer policy REPLACES it, because the old record was given in
//! terms that no longer hold. Two grants written at once must both survive, so a write reads the record, merges,
//! and writes back only over the revision it read; a refused write reads again and retries, bounded.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_constants::CONSENT_WRITE_ATTEMPTS;
use tessari_oauth_core::consents::{ConsentRequest, Coverage, coverage};
use tessari_oauth_infrastructure::tessaridb::Place;
use tessari_oauth_types::{
    ClientId, ErrorCategory, Resource, ScopeSet, TenantId, Timestamp, UserId,
};

use super::repository::ConsentRepository;
use super::{Consent, ConsentEntity, NewGrant, Revocation, Revoker};
use crate::retry::{self, Again};
use crate::{Error, Result, Tenancy};

/// Users' grants to clients.
#[derive(Clone)]
pub struct ConsentService {
    repository: Arc<dyn ConsentRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "consent",
        reason: reason.to_owned(),
    }
}

/// The record id of `user`'s grant to `client`. A user id never holds a space, so the first space ends it and no
/// two pairs share an id.
fn record_id(user: &UserId, client: &ClientId) -> String {
    format!("{} {}", user.as_str(), client.as_str())
}

/// A write of the record lost to another writer, whether the store says so as a conflict or as a `retry`: that
/// writer committed, and the write is read, merged and tried again after the short pause. Waiting longer only lets
/// the other losers collide again.
fn contended(failure: &Error) -> Again {
    match failure {
        Error::Store(store) if store.category() == ErrorCategory::Conflict => Again::Soon,
        _ => Again::No,
    }
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| unreadable("time beyond i64"))
}

fn to_model(row: ConsentEntity) -> Result<Consent> {
    let revoked = match (row.revoked_at, row.revoked_by) {
        (None, None) => None,
        (Some(at), Some(by)) => Some(Revocation {
            at: Timestamp::from_unix_secs(
                u64::try_from(at).map_err(|_| unreadable("negative revocation"))?,
            ),
            by: Revoker::read(&by).ok_or_else(|| unreadable("revoked_by"))?,
        }),
        _ => return Err(unreadable("a revocation without its time or its actor")),
    };
    let resources = row
        .resources
        .into_iter()
        .map(|resource| Resource::parse(resource).map_err(|_| unreadable("resources")))
        .collect::<Result<BTreeSet<Resource>>>()?;
    Ok(Consent {
        tenant: TenantId::parse(row.tenant).map_err(|_| unreadable("tenant"))?,
        user: UserId::parse(row.user_id).map_err(|_| unreadable("user_id"))?,
        client_id: ClientId::parse(row.client_id).map_err(|_| unreadable("client_id"))?,
        scopes: ScopeSet::parse(&row.scopes.join(" ")).map_err(|_| unreadable("scopes"))?,
        resources,
        policy_version: u32::try_from(row.policy_version)
            .map_err(|_| unreadable("policy_version"))?,
        shown_version: row.shown_version,
        granted_at: Timestamp::from_unix_secs(
            u64::try_from(row.granted_at).map_err(|_| unreadable("granted_at"))?,
        ),
        revoked,
    })
}

impl ConsentService {
    pub(crate) fn new(repository: Arc<dyn ConsentRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Record `grant`, widening a standing grant under the same policy, and answer the record as written.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses for a reason other than a concurrent write, or holds a row this
    /// crate cannot read — and when concurrent writes keep winning after every attempt is spent.
    pub async fn grant(&self, grant: &NewGrant) -> Result<Consent> {
        let place = self.tenancy.place(&grant.tenant)?;
        let id = record_id(&grant.user, &grant.client_id);
        retry::bounded(CONSENT_WRITE_ATTEMPTS, contended, || {
            self.write_once(&place, &id, grant)
        })
        .await
    }

    async fn write_once(&self, place: &Place, id: &str, grant: &NewGrant) -> Result<Consent> {
        let existing = self.repository.find(place, id).await?;
        let standing = match &existing {
            Some(row) => Some(to_model(row.clone())?),
            None => None,
        };
        let (scopes, resources) = match standing {
            Some(consent)
                if consent.revoked.is_none() && consent.policy_version == grant.policy_version =>
            {
                (
                    consent.scopes.union(&grant.request.scopes),
                    consent
                        .resources
                        .union(&grant.request.resources)
                        .cloned()
                        .collect(),
                )
            }
            _ => (
                grant.request.scopes.clone(),
                grant.request.resources.clone(),
            ),
        };
        let revision = match &existing {
            Some(row) => row
                .revision
                .checked_add(1)
                .ok_or_else(|| unreadable("revision overflow"))?,
            None => 1,
        };
        let entity = ConsentEntity {
            tenant: grant.tenant.as_str().to_owned(),
            user_id: grant.user.as_str().to_owned(),
            client_id: grant.client_id.as_str().to_owned(),
            scopes: scopes.iter().map(str::to_owned).collect(),
            resources: resources
                .iter()
                .map(|resource: &Resource| resource.as_str().to_owned())
                .collect(),
            policy_version: i64::from(grant.policy_version),
            shown_version: grant.shown_version.clone(),
            granted_at: seconds(grant.at)?,
            revision,
            revoked_at: None,
            revoked_by: None,
        };
        match &existing {
            None => self.repository.create(place, id, &entity).await?,
            Some(row) => {
                self.repository
                    .replace(place, id, &entity, row.revision)
                    .await?
            }
        }
        to_model(entity)
    }

    /// Whether `request` from `client` is inside `user`'s grant under `policy_version`, or what must be asked.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or holds a row this crate cannot read.
    pub async fn check(
        &self,
        tenant: &TenantId,
        user: &UserId,
        client: &ClientId,
        request: &ConsentRequest,
        policy_version: u32,
    ) -> Result<Coverage> {
        let place = self.tenancy.place(tenant)?;
        let standing = self
            .repository
            .find(&place, &record_id(user, client))
            .await?
            .map(to_model)
            .transpose()?;
        Ok(coverage(
            standing.as_ref().map(Consent::as_granted).as_ref(),
            request,
            policy_version,
        ))
    }

    /// Every grant `user` has given, revoked ones included, for the user's own grant list.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or holds a row this crate cannot read.
    pub async fn list(&self, tenant: &TenantId, user: &UserId) -> Result<Vec<Consent>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .list_for_user(&place, user.as_str())
            .await?
            .into_iter()
            .map(to_model)
            .collect()
    }

    /// End `user`'s grant to `client`, recording `by`; answers whether a standing grant was ended by this call.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses for a reason other than there being nothing standing to revoke, or
    /// holds a row this crate cannot read.
    pub async fn revoke(
        &self,
        tenant: &TenantId,
        user: &UserId,
        client: &ClientId,
        by: &Revoker,
        at: Timestamp,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let id = record_id(user, client);
        let at = seconds(at)?;
        let spelled = by.spelled();
        let outcome = retry::bounded(CONSENT_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.revoke(&place, &id, at, &spelled)
        })
        .await;
        match outcome {
            Ok(before) => Ok(before.is_some()),
            // The store said no: either nothing stands at this id, or it is already revoked — or something else.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                match self.repository.find(&place, &id).await? {
                    None => Ok(false),
                    Some(row) if row.revoked_at.is_some() => Ok(false),
                    Some(_) => Err(refusal),
                }
            }
            Err(failure) => Err(failure),
        }
    }
}
