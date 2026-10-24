//! The account-event cascade: an event names exactly what it revokes — every standing family of a user, of a client,
//! or of one user at one client — and each is revoked for the event's reason, the whole cascade recorded in the audit
//! trail as one message naming whose families, why, and how many.

use tessari_oauth_types::{TenantId, Timestamp};

use tessari_oauth_constants::REFRESH_ROTATE_ATTEMPTS;

use super::service::seconds;
use super::{Holder, RefreshService};
use crate::audit::{AuditEvent, AuditKind};
use crate::{Error, Result, retry};

impl RefreshService {
    /// Revoke every family `holder` names in `tenant` that stands at `now`, for `reason`, in one transaction, record
    /// it, and answer how many it revoked. A family revoked meanwhile by another request keeps the reason it was
    /// given.
    ///
    /// # Errors
    ///
    /// When the store is unavailable, refuses after the bounded retries, or answers something other than a count.
    pub async fn revoke_standing(
        &self,
        tenant: &TenantId,
        holder: &Holder<'_>,
        reason: &str,
        now: Timestamp,
    ) -> Result<usize> {
        let place = self.tenancy.place(tenant)?;
        let at = seconds(now)?;
        let revoked = retry::bounded(REFRESH_ROTATE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.revoke_standing(&place, holder, at, reason)
        })
        .await?;
        let (user, client_id) = match holder {
            Holder::User(user) => (Some(*user), None),
            Holder::Client(client) => (None, Some(*client)),
            Holder::Grant { user, client } => (Some(*user), Some(*client)),
        };
        let event = AuditEvent {
            client_id: client_id.cloned(),
            user: user.cloned(),
            reason: Some(reason.to_owned()),
            families: Some(revoked),
            ..AuditEvent::of(AuditKind::Cascade)
        };
        self.audit.record(tenant, &event, now).await?;
        usize::try_from(revoked).map_err(|_| Error::Invalid {
            record: "refresh family",
            reason: "a count beyond usize",
        })
    }
}
