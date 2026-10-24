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
use tessari_oauth_core::mail_template::{self, MailKind, Placeholder, Rendered};
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_storage::audit::{AuditEvent, AuditKind, AuditService};
use tessari_oauth_storage::companies::Served;
use tessari_oauth_storage::email_changes::{DueChange, EmailChangeService};
use tessari_oauth_storage::mail_templates::MailTemplateService;
use tessari_oauth_storage::outbox::{NewMail, OutboxService};
use tessari_oauth_types::{Clock, EmailAddress, TenantId, Timestamp};

use crate::daemon::{Daemon, DaemonFuture, DaemonReport};
use crate::{Error, Result};

const NAME: &str = "email-change-apply";

/// The address-change daemon and everything a run needs.
pub struct EmailChangeApply {
    /// The requested changes.
    pub email_changes: Arc<EmailChangeService>,
    /// The wording of the mail the server sends.
    pub mail_templates: Arc<MailTemplateService>,
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
                let new = change.new_address.as_str();
                let values = [
                    (Placeholder::Issuer, issuer),
                    (Placeholder::NewAddress, new),
                ];
                self.notify(
                    tenant,
                    MailKind::EmailAppliedOld,
                    &change.old_address,
                    &values,
                )
                .await;
                let values = [(Placeholder::Issuer, issuer)];
                self.notify(
                    tenant,
                    MailKind::EmailAppliedNew,
                    &change.new_address,
                    &values,
                )
                .await;
                self.record(tenant, change, "applied", now).await;
            } else {
                self.email_changes
                    .discard(tenant, change)
                    .await
                    .map_err(|failure| store(&failure))?;
                tally.refused = tally.refused.saturating_add(1);
                let values = [(Placeholder::Issuer, issuer)];
                self.notify(tenant, MailKind::EmailRefused, &change.old_address, &values)
                    .await;
                self.record(tenant, change, "refused", now).await;
            }
        }
        Ok(())
    }

    /// Queue `kind`'s notice to `to` in `tenant`'s wording; a notice that cannot be queued is logged and never undoes
    /// the change it reports.
    async fn notify(
        &self,
        tenant: &TenantId,
        kind: MailKind,
        to: &EmailAddress,
        values: &[(Placeholder, &str)],
    ) {
        let queued = async {
            let template = self.mail_templates.resolve(tenant, kind).await?;
            // The shipped wording always renders with the values its kind carries.
            let Some(Rendered { subject, text }) = mail_template::compose(kind, &template, values)
            else {
                return Ok(());
            };
            let mail = NewMail {
                to: Some(to.clone()),
                subject,
                text,
            };
            self.outbox.enqueue(tenant, &self.kek, &mail).await
        };
        if let Err(failure) = queued.await {
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
