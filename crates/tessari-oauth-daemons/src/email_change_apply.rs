//! The address-change daemon: applies a change of sign-in address once the new address has confirmed it and its
//! hold is over.
//!
//! For each company a run takes the changes that are due and applies each in one transaction. An applied change is
//! recorded and told to both addresses. A change the store refuses, because the new address has meanwhile become
//! another account's, is dropped, recorded and told to the old address, which still signs in. A notice carries no
//! link, and no address appears in any log line.

use std::sync::Arc;
use std::time::Duration;

use tessari_oauth_constants::EMAIL_CHANGE_APPLY_BATCH;
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind, AuditService};
use tessari_oauth_storage::companies::Served;
use tessari_oauth_storage::email_changes::{DueChange, EmailChangeService};
use tessari_oauth_storage::outbox::{NewMail, OutboxService};
use tessari_oauth_types::{Clock, TenantId, Timestamp};

use crate::daemon::{Daemon, DaemonFuture, DaemonReport};
use crate::{Error, Result};

const NAME: &str = "email-change-apply";

/// The subject of the notices of an applied change.
const CHANGED_SUBJECT: &str = "Your sign-in address has changed";

/// The subject of the notice of a refused change.
const UNCHANGED_SUBJECT: &str = "Your sign-in address was not changed";

/// The address-change daemon and everything a run needs.
pub struct EmailChangeApply {
    /// The requested changes.
    pub email_changes: Arc<EmailChangeService>,
    /// The mail queue notices go to.
    pub outbox: Arc<OutboxService>,
    /// The audit trail.
    pub audit: Arc<AuditService>,
    /// The key-encryption key queued mail is sealed under.
    pub kek: Arc<Kek>,
    /// The companies this node serves, each with its issuer.
    pub served: Arc<Served>,
    /// The run's clock.
    pub clock: Clock,
    /// How often it runs.
    pub interval: Duration,
    /// The most one run may take.
    pub timeout: Duration,
}

impl EmailChangeApply {
    async fn run(&self) -> Result<DaemonReport> {
        let mut tally = Tally::default();
        let companies = self.served.issuers();
        for (tenant, issuer) in &companies {
            self.apply_tenant(tenant, issuer, &mut tally).await?;
        }
        Ok(DaemonReport {
            message: format!(
                "tenants={} applied={} refused={}",
                companies.len(),
                tally.applied,
                tally.refused
            ),
        })
    }

    async fn apply_tenant(&self, tenant: &TenantId, issuer: &str, tally: &mut Tally) -> Result<()> {
        let now = (self.clock)();
        let due = self
            .email_changes
            .due(tenant, now, EMAIL_CHANGE_APPLY_BATCH)
            .await
            .map_err(|failure| store(&failure))?;
        for change in &due {
            let applied = self
                .email_changes
                .apply(tenant, change)
                .await
                .map_err(|failure| store(&failure))?;
            // The change is settled once the store answers, so what follows is told and recorded but never undoes it.
            if applied {
                tally.applied = tally.applied.saturating_add(1);
                self.notify(tenant, &applied_to_old(issuer, change)).await;
                self.notify(tenant, &applied_to_new(issuer, change)).await;
                self.record(tenant, change, "applied", now).await;
            } else {
                self.email_changes
                    .discard(tenant, change)
                    .await
                    .map_err(|failure| store(&failure))?;
                tally.refused = tally.refused.saturating_add(1);
                self.notify(tenant, &refused_to_old(issuer, change)).await;
                self.record(tenant, change, "refused", now).await;
            }
        }
        Ok(())
    }

    async fn notify(&self, tenant: &TenantId, mail: &NewMail) {
        if let Err(failure) = self.outbox.enqueue(tenant, &self.kek, mail).await {
            tracing::error!(
                daemon = NAME,
                event = "notice_unqueued",
                tenant = tenant.as_str(),
                category = ?failure.category(),
                "a notice of an address change could not be queued"
            );
        }
    }

    async fn record(&self, tenant: &TenantId, change: &DueChange, how: &str, now: Timestamp) {
        let event = AuditEvent {
            user: Some(change.user.clone()),
            reason: Some(how.to_owned()),
            ..AuditEvent::of(AuditKind::AddressChanged)
        };
        if let Err(failure) = self.audit.record(tenant, &event, now).await {
            tracing::error!(
                daemon = NAME,
                event = "audit_unrecorded",
                tenant = tenant.as_str(),
                category = ?failure.category(),
                "an address change could not be appended to the audit trail"
            );
        }
    }
}

/// What a run did.
#[derive(Default)]
struct Tally {
    applied: usize,
    refused: usize,
}

fn store(failure: &tessari_oauth_storage::Error) -> Error {
    Error::Run {
        daemon: NAME,
        message: failure.to_string(),
        category: failure.category(),
    }
}

/// The notice to the old address that the account no longer signs in with it.
fn applied_to_old(issuer: &str, change: &DueChange) -> NewMail {
    let new = change.new_address.as_str();
    NewMail {
        to: Some(change.old_address.clone()),
        subject: CHANGED_SUBJECT.to_owned(),
        text: format!(
            "Your account at {issuer} now signs in with {new} instead of this address.\n\n\
             If you did not ask for this, contact the administrator of that sign-in service.\n"
        ),
    }
}

/// The notice to the new address that the account now signs in with it.
fn applied_to_new(issuer: &str, change: &DueChange) -> NewMail {
    NewMail {
        to: Some(change.new_address.clone()),
        subject: CHANGED_SUBJECT.to_owned(),
        text: format!("Your account at {issuer} now signs in with this address.\n"),
    }
}

/// The notice to the old address that the change did not take effect.
fn refused_to_old(issuer: &str, change: &DueChange) -> NewMail {
    NewMail {
        to: Some(change.old_address.clone()),
        subject: UNCHANGED_SUBJECT.to_owned(),
        text: format!(
            "The change of the address your account at {issuer} signs in with did not take effect, and this \
             address still signs in.\n\nYou can ask for the change again from your account page.\n"
        ),
    }
}

impl Daemon for EmailChangeApply {
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
