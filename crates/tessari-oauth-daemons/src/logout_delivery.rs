//! The back-channel logout daemon (OpenID Connect Back-Channel Logout 1.0): tells the clients of ended sessions.
//!
//! For each tenant a run claims the deliveries that are due. For each client a delivery names it signs a logout token
//! addressed to that client alone, with the subject that client knows the user by, and hands it to the sender. A
//! client that was told, or that registered no back-channel URI and so cannot be told, is done; one that was not told
//! stays on the delivery, which is released to be due again later, so the queue's attempt bound limits how long a
//! client that never answers is retried. No token appears in any log line.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tessari_oauth_constants::{LOGOUT_CLAIM_BATCH, LOGOUT_RETRY_FIRST_SECS, LOGOUT_RETRY_MAX_SECS};
use tessari_oauth_core::logout::{Ended, LOGOUT_TOKEN_TYPE, logout_claims};
use tessari_oauth_infrastructure::custody::{Kek, token_id};
use tessari_oauth_storage::clients::ClientService;
use tessari_oauth_storage::keys::KeyService;
use tessari_oauth_storage::logouts::{Delivery, LogoutService};
use tessari_oauth_storage::subjects::SubjectService;
use tessari_oauth_types::{ClientId, Clock, ErrorCategory, TenantId, Timestamp};

use crate::daemon::{Daemon, DaemonFuture, DaemonReport};
use crate::{Error, Result};

const NAME: &str = "logout-delivery";

/// Where a logout token is sent: an HTTP `POST` of `logout_token` to the client's back-channel URI.
pub trait LogoutSender: Send + Sync {
    /// Send `logout_token` to `uri`; whether the client answered that it was told.
    fn send<'a>(
        &'a self,
        uri: &'a str,
        logout_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// The delivery daemon and everything a run needs.
pub struct LogoutDelivery {
    /// The deliveries owed.
    pub logouts: Arc<LogoutService>,
    /// The clients' registrations, for their back-channel URIs.
    pub clients: Arc<ClientService>,
    /// The pairwise subjects each client knows a user by.
    pub subjects: Arc<SubjectService>,
    /// The tenants' signing keys.
    pub keys: Arc<KeyService>,
    /// The key-encryption key signing keys and salts are sealed under.
    pub kek: Arc<Kek>,
    /// The tenants this server serves, each with its issuer.
    pub tenants: Vec<(TenantId, String)>,
    /// Where tokens go.
    pub sender: Arc<dyn LogoutSender>,
    /// The run's clock.
    pub clock: Clock,
    /// How often it runs.
    pub interval: Duration,
    /// The most one run may take.
    pub timeout: Duration,
}

/// What a run did.
#[derive(Default)]
struct Tally {
    sessions: usize,
    told: usize,
    untold: usize,
    finished: usize,
    retried: usize,
}

fn failed(message: impl Into<String>, category: ErrorCategory) -> Error {
    Error::Run {
        daemon: NAME,
        message: message.into(),
        category,
    }
}

fn store(failure: &tessari_oauth_storage::Error) -> Error {
    failed(failure.to_string(), failure.category())
}

/// How long a delivery claimed `attempts` times waits before it is due again: doubling from the first delay, capped.
fn backoff(attempts: u32) -> u64 {
    let doublings = attempts.saturating_sub(1).min(20);
    LOGOUT_RETRY_FIRST_SECS
        .saturating_mul(1_u64 << doublings)
        .min(LOGOUT_RETRY_MAX_SECS)
}

impl LogoutDelivery {
    async fn run(&self) -> Result<DaemonReport> {
        let mut tally = Tally::default();
        for (tenant, issuer) in &self.tenants {
            self.deliver_tenant(tenant, issuer, &mut tally).await?;
        }
        Ok(DaemonReport {
            message: format!(
                "tenants={} sessions={} told={} untold={} finished={} retried={}",
                self.tenants.len(),
                tally.sessions,
                tally.told,
                tally.untold,
                tally.finished,
                tally.retried
            ),
        })
    }

    async fn deliver_tenant(
        &self,
        tenant: &TenantId,
        issuer: &str,
        tally: &mut Tally,
    ) -> Result<()> {
        let deliveries = self
            .logouts
            .claim(tenant, LOGOUT_CLAIM_BATCH)
            .await
            .map_err(|failure| store(&failure))?;
        for delivery in deliveries {
            tally.sessions = tally.sessions.saturating_add(1);
            let mut untold = Vec::new();
            for client in &delivery.clients {
                if self.tell(tenant, issuer, &delivery, client).await? {
                    tally.told = tally.told.saturating_add(1);
                } else {
                    tally.untold = tally.untold.saturating_add(1);
                    untold.push(client.clone());
                }
            }
            if untold.is_empty() {
                self.logouts
                    .finish(tenant, &delivery.id)
                    .await
                    .map_err(|failure| store(&failure))?;
                tally.finished = tally.finished.saturating_add(1);
            } else {
                self.logouts
                    .retry(tenant, &delivery.id, &untold, backoff(delivery.attempts))
                    .await
                    .map_err(|failure| store(&failure))?;
                tally.retried = tally.retried.saturating_add(1);
            }
        }
        Ok(())
    }

    /// Tell `client` that `delivery`'s session ended; whether it is done with: told, or nowhere to tell it.
    async fn tell(
        &self,
        tenant: &TenantId,
        issuer: &str,
        delivery: &Delivery,
        client: &ClientId,
    ) -> Result<bool> {
        let registration = self
            .clients
            .find(tenant, client)
            .await
            .map_err(|failure| store(&failure))?;
        let Some(uri) = registration.and_then(|found| found.backchannel_logout_uri) else {
            return Ok(true);
        };
        let now: Timestamp = (self.clock)();
        let subject = self
            .subjects
            .pairwise(tenant, &self.kek, client, &delivery.user, now)
            .await
            .map_err(|failure| store(&failure))?;
        let signer = self
            .keys
            .signer(tenant, &self.kek, now)
            .await
            .map_err(|failure| store(&failure))?;
        let jti =
            token_id().map_err(|failure| failed(failure.to_string(), ErrorCategory::Internal))?;
        let ended = Ended {
            issuer,
            client_id: client,
            subject: &subject,
            session_id: &delivery.sid,
        };
        let payload = serde_json::to_vec(&logout_claims(&ended, &jti, now))
            .map_err(|failure| failed(failure.to_string(), ErrorCategory::Internal))?;
        let token = signer
            .sign_compact(LOGOUT_TOKEN_TYPE, &payload)
            .map_err(|failure| failed(failure.to_string(), ErrorCategory::Internal))?;
        let told = self.sender.send(uri.as_str(), &token).await;
        if !told {
            tracing::warn!(
                event = "logout_untold",
                tenant = tenant.as_str(),
                client = client.as_str(),
                attempts = delivery.attempts,
                "a client was not told that a session ended; the delivery is retried"
            );
        }
        Ok(told)
    }
}

impl Daemon for LogoutDelivery {
    fn name(&self) -> &'static str {
        NAME
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn run_once(&self) -> DaemonFuture<'_> {
        Box::pin(self.run())
    }
}

#[cfg(test)]
mod tests {
    use tessari_oauth_constants::{LOGOUT_RETRY_FIRST_SECS, LOGOUT_RETRY_MAX_SECS};

    use super::backoff;

    #[test]
    fn the_wait_doubles_from_the_first_and_stops_at_the_longest() {
        assert_eq!(backoff(1), LOGOUT_RETRY_FIRST_SECS);
        assert_eq!(backoff(2), LOGOUT_RETRY_FIRST_SECS * 2);
        assert_eq!(backoff(4), LOGOUT_RETRY_FIRST_SECS * 8);
        assert_eq!(backoff(64), LOGOUT_RETRY_MAX_SECS);
        assert_eq!(
            backoff(0),
            LOGOUT_RETRY_FIRST_SECS,
            "a claim always counts at least one"
        );
    }
}
