//! Removing a client: its registration goes first, so nothing new can start for it, and then everything it held ends.
//! Every user's grant to it is revoked as `client-removed`, kept as a revoked record so a client registered later under
//! the same id inherits nothing, and every refresh family it held is revoked. A removal sent again finds the
//! registration gone and finishes whatever the first one left standing. The console's own client is not removed.

use tessari_oauth_constants::ADMIN_CONSOLE_CLIENT;
use tessari_oauth_types::{ClientId, TenantId, Timestamp};

use crate::consents::Revoker;
use crate::refresh::Holder;
use crate::{Error, Result, Storage};

/// The reason a removed client's refresh families are recorded under.
const CLIENT_REMOVED: &str = "client_removed";

/// What removing a client ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Removed {
    /// Whether the registration was there to delete.
    pub registered: bool,
    /// How many users' grants to it were ended.
    pub consents: usize,
    /// How many of its refresh families were ended.
    pub families: usize,
}

impl Storage {
    /// Remove `client` from `tenant` at `now` and end every grant and refresh family it held.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for the console's own client, with nothing changed; and the store's failures, after which
    /// sending the removal again completes it.
    pub async fn remove_client(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        now: Timestamp,
    ) -> Result<Removed> {
        if client.as_str() == ADMIN_CONSOLE_CLIENT {
            return Err(Error::Invalid {
                record: "client",
                reason: "the console's own client is not removed",
            });
        }
        let registered = self.clients.remove(tenant, client).await?;
        let mut consents = 0_usize;
        for user in self.consents.standing_for(tenant, client).await? {
            if self
                .consents
                .revoke(tenant, &user, client, &Revoker::ClientRemoved, now)
                .await?
            {
                consents = consents.saturating_add(1);
            }
        }
        let families = self
            .refresh
            .revoke_standing(tenant, &Holder::Client(client), CLIENT_REMOVED, now)
            .await?;
        Ok(Removed {
            registered,
            consents,
            families,
        })
    }
}
