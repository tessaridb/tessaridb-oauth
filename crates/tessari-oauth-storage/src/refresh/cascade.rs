//! The account-event cascade: an event names exactly what it revokes — every standing family of a user, of a client,
//! or of one user at one client — and each is revoked for the event's reason.

use tessari_oauth_types::{TenantId, Timestamp};

use super::service::seconds;
use super::{Holder, RefreshService};
use crate::Result;

impl RefreshService {
    /// Revoke every family `holder` names in `tenant` that stands at `now`, for `reason`, and answer how many stood.
    /// A family revoked meanwhile by another request keeps the reason it was given.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses for a reason other than a family being revoked already, or holds a row
    /// this crate cannot read.
    pub async fn revoke_standing(
        &self,
        tenant: &TenantId,
        holder: &Holder<'_>,
        reason: &str,
        now: Timestamp,
    ) -> Result<usize> {
        let place = self.tenancy.place(tenant)?;
        let at = seconds(now)?;
        // The store changes many records only one by one, each by its id: read the standing ones, then end each.
        let standing = self.repository.standing(&place, holder).await?;
        for family_id in &standing {
            self.end_family(&place, family_id, at, reason).await?;
        }
        Ok(standing.len())
    }
}
