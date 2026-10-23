//! The mail daemon: sends the mail companies queued, through the operator's relay.
//!
//! For each company a run claims the queued mails that are due and hands every one to the sender at once, each
//! bounded by a timeout, so a run ends well before the claims' hold lapses. A mail the relay took is done; a mail
//! queued for no account is dropped unsent, which is what makes such a request cost what any other costs; a mail the
//! relay did not take is released to be tried later, and dropped after its last try, since the link it carries
//! expires anyway. No address, subject or text appears in any log line.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use tessari_oauth_constants::{
    MAIL_ATTEMPTS, MAIL_CLAIM_BATCH, MAIL_RETRY_FIRST_SECS, MAIL_SEND_TIMEOUT_SECS,
};
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_infrastructure::mail::{MailRelay, OutgoingMail};
use tessari_oauth_storage::companies::Served;
use tessari_oauth_storage::outbox::{OutboxService, QueuedMail};
use tessari_oauth_types::TenantId;

use crate::daemon::{Daemon, DaemonFuture, DaemonReport};
use crate::{Error, Result};

const NAME: &str = "mail-delivery";

/// Where a mail goes: the operator's relay, in production.
pub trait MailSender: Send + Sync {
    /// Submit `mail`; whether the relay took it.
    fn send<'a>(
        &'a self,
        mail: &'a OutgoingMail,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// The relay: why a mail was not taken is logged here, since the daemon sees only that it was not.
impl MailSender for MailRelay {
    fn send<'a>(
        &'a self,
        mail: &'a OutgoingMail,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            match Self::send(self, mail).await {
                Ok(()) => true,
                Err(reason) => {
                    tracing::warn!(event = "mail_unsent", %reason, "the relay did not take a mail");
                    false
                }
            }
        })
    }
}

/// The mail daemon and everything a run needs.
pub struct MailDelivery {
    /// The queued mail.
    pub outbox: Arc<OutboxService>,
    /// The key-encryption key mail is sealed under.
    pub kek: Arc<Kek>,
    /// The companies this node serves.
    pub served: Arc<Served>,
    /// Where mail goes.
    pub sender: Arc<dyn MailSender>,
    /// How often it runs.
    pub interval: Duration,
    /// The most one run may take.
    pub timeout: Duration,
}

/// How long a mail the relay did not take after `attempts` tries waits before the next, doubling from the first
/// delay; `None` after the last try, when it is dropped.
fn next_try(attempts: u32) -> Option<u64> {
    if attempts >= MAIL_ATTEMPTS {
        return None;
    }
    let doublings = attempts.saturating_sub(1);
    Some(MAIL_RETRY_FIRST_SECS.saturating_mul(1_u64 << doublings))
}

/// What a run did.
#[derive(Default)]
struct Tally {
    sent: usize,
    unsent: usize,
    dropped: usize,
    retried: usize,
    abandoned: usize,
}

fn store(failure: &tessari_oauth_storage::Error) -> Error {
    Error::Run {
        daemon: NAME,
        message: failure.to_string(),
        category: failure.category(),
    }
}

impl MailDelivery {
    async fn run(&self) -> Result<DaemonReport> {
        let mut tally = Tally::default();
        let companies = self.served.issuers();
        for (tenant, _) in &companies {
            self.deliver_tenant(tenant, &mut tally).await?;
        }
        Ok(DaemonReport {
            message: format!(
                "tenants={} sent={} unsent={} dropped={} retried={} abandoned={}",
                companies.len(),
                tally.sent,
                tally.unsent,
                tally.dropped,
                tally.retried,
                tally.abandoned
            ),
        })
    }

    async fn deliver_tenant(&self, tenant: &TenantId, tally: &mut Tally) -> Result<()> {
        let mails = self
            .outbox
            .claim(tenant, &self.kek, MAIL_CLAIM_BATCH)
            .await
            .map_err(|failure| store(&failure))?;
        // Every claimed mail is handed over at once, so a slow relay cannot keep the later ones past their hold.
        let outcomes = join_all(mails.iter().map(|mail| self.handed(mail))).await;
        for (mail, outcome) in mails.iter().zip(outcomes) {
            match outcome {
                Handed::Sent => tally.sent = tally.sent.saturating_add(1),
                Handed::NoRecipient => tally.dropped = tally.dropped.saturating_add(1),
                Handed::Unsent => {
                    tally.unsent = tally.unsent.saturating_add(1);
                    if let Some(after_secs) = next_try(mail.attempts) {
                        self.outbox
                            .retry(tenant, &mail.id, after_secs)
                            .await
                            .map_err(|failure| store(&failure))?;
                        tally.retried = tally.retried.saturating_add(1);
                        continue;
                    }
                    tracing::warn!(
                        event = "mail_abandoned",
                        tenant = tenant.as_str(),
                        attempts = mail.attempts,
                        "a mail the relay never took is dropped after its last try"
                    );
                    tally.abandoned = tally.abandoned.saturating_add(1);
                }
            }
            self.outbox
                .finish(tenant, &mail.id)
                .await
                .map_err(|failure| store(&failure))?;
        }
        Ok(())
    }

    /// Hand `mail` to the sender, bounded by the send timeout; a mail with no recipient is not handed over.
    async fn handed(&self, mail: &QueuedMail) -> Handed {
        let Some(to) = mail.to.clone() else {
            return Handed::NoRecipient;
        };
        let outgoing = OutgoingMail {
            to,
            subject: mail.subject.clone(),
            text: mail.text.clone(),
        };
        let taken = tokio::time::timeout(
            Duration::from_secs(MAIL_SEND_TIMEOUT_SECS),
            self.sender.send(&outgoing),
        )
        .await
        .unwrap_or(false);
        if taken { Handed::Sent } else { Handed::Unsent }
    }
}

/// What became of one claimed mail.
enum Handed {
    Sent,
    NoRecipient,
    Unsent,
}

impl Daemon for MailDelivery {
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
    use tessari_oauth_constants::{MAIL_ATTEMPTS, MAIL_RETRY_FIRST_SECS};

    use super::next_try;

    #[test]
    fn the_wait_doubles_from_the_first() {
        assert_eq!(next_try(1), Some(MAIL_RETRY_FIRST_SECS));
        assert_eq!(next_try(2), Some(MAIL_RETRY_FIRST_SECS * 2));
        assert_eq!(next_try(3), Some(MAIL_RETRY_FIRST_SECS * 4));
        assert_eq!(
            next_try(MAIL_ATTEMPTS - 1),
            Some(MAIL_RETRY_FIRST_SECS * 16)
        );
    }

    #[test]
    fn the_last_try_is_the_last() {
        assert_eq!(next_try(MAIL_ATTEMPTS), None);
        assert_eq!(next_try(MAIL_ATTEMPTS + 1), None);
    }
}
