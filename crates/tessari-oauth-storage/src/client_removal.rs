//! Removing a client: its registration goes first, so nothing new can start for it, and then everything it held ends.
//! Every user's grant to it is revoked as `client-removed`, kept as a revoked record so a client registered later under
//! the same id inherits nothing, and every refresh family it held is revoked. A removal sent again finds the
//! registration gone and finishes whatever the first one left standing. The console's own client is not removed.

use std::sync::Arc;

use tessari_oauth_constants::ADMIN_CONSOLE_CLIENT;
use tessari_oauth_types::{ClientId, TenantId, Timestamp};

use crate::clients::ClientService;
use crate::consents::{ConsentService, Revoker};
use crate::refresh::{Holder, RefreshService};
use crate::{Error, Result};

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

/// Removes clients, through the three services whose records a client holds.
pub struct ClientRemovalService {
    clients: Arc<ClientService>,
    consents: Arc<ConsentService>,
    refresh: Arc<RefreshService>,
}

impl ClientRemovalService {
    /// Remove clients through `clients`, `consents` and `refresh`.
    #[must_use]
    pub fn new(
        clients: Arc<ClientService>,
        consents: Arc<ConsentService>,
        refresh: Arc<RefreshService>,
    ) -> Self {
        Self {
            clients,
            consents,
            refresh,
        }
    }

    /// Remove `client` from `tenant` at `now` and end every grant and refresh family it held.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for the console's own client, with nothing changed; and the store's failures, after which
    /// sending the removal again completes it.
    pub async fn remove(
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
