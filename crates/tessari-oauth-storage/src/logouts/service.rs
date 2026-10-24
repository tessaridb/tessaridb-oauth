//! The logout service: the deliveries a tenant owes its clients, claimed by the worker that tells them and finished
//! once every client named was told.

use std::sync::Arc;

use tessari_oauth_types::{ClientId, TenantId, UserId};

use super::entity::ClaimedEntity;
use super::repository::LogoutRepository;
use super::{Delivery, DeliveryEntity};
use crate::{Error, Result, Tenancy, answers};

/// Owed logouts in every tenant of a region.
pub struct LogoutService {
    repository: Arc<dyn LogoutRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "logout delivery",
        reason: reason.to_owned(),
    }
}

impl LogoutService {
    pub(crate) fn new(repository: Arc<dyn LogoutRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Claim at most `count` of `tenant`'s deliveries that are due; each stays held by this claim until it is
    /// finished or its hold lapses.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record this service did not write.
    pub async fn claim(&self, tenant: &TenantId, count: u32) -> Result<Vec<Delivery>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .claim(&place, count)
            .await?
            .into_iter()
            .map(delivery)
            .collect()
    }

    /// Keep only `clients` on `tenant`'s delivery `id`, the ones still to be told, and release it to be claimed again
    /// `after_secs` from now.
    ///
    /// # Errors
    ///
    /// Store failures, among them the refusal of a release whose hold already lapsed and was taken by another claim.
    pub async fn retry(
        &self,
        tenant: &TenantId,
        id: &str,
        clients: &[ClientId],
        after_secs: u64,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let clients: Vec<String> = clients
            .iter()
            .map(|client| client.as_str().to_owned())
            .collect();
        self.repository
            .retry(&place, id, &clients, after_secs)
            .await
    }

    /// Delete `tenant`'s delivery `id`, once; `false` when there was none.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn finish(&self, tenant: &TenantId, id: &str) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        Ok(self.repository.finish(&place, id).await?.is_some())
    }
}

/// The delivery a claimed row holds.
fn delivery(claimed: ClaimedEntity) -> Result<Delivery> {
    let ClaimedEntity { spelled, delivery } = claimed;
    let DeliveryEntity {
        user_id,
        sid,
        clients,
        attempts,
    } = delivery;
    Ok(Delivery {
        id: answers::text_id(&spelled, "logout delivery")?,
        user: UserId::parse(user_id).map_err(|_| unreadable("user_id"))?,
        sid,
        clients: clients
            .into_iter()
            .map(ClientId::parse)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| unreadable("clients"))?,
        attempts: attempts
            .map(u32::try_from)
            .transpose()
            .map_err(|_| unreadable("attempts"))?
            .unwrap_or_default(),
    })
}
