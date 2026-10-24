//! The outbox service: mail queued sealed by the flow that owes it, claimed and opened by the worker that sends it.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tessari_oauth_infrastructure::custody::{Kek, token_id};
use tessari_oauth_types::{EmailAddress, TenantId, base64url};
use zeroize::Zeroizing;

use super::entity::ClaimedEntity;
use super::repository::OutboxRepository;
use super::{MailEntity, NewMail, QueuedMail};
use crate::{Error, Result, Tenancy, answers};

/// What a mail is sealed as: everything it says, so neither the address nor a link token is readable at rest.
#[derive(Serialize, Deserialize)]
struct Sealed {
    to: Option<String>,
    subject: String,
    text: String,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "queued mail",
        reason: reason.to_owned(),
    }
}

/// What a mail is sealed for: its own record, so a sealed value copied onto another record does not open.
pub(crate) fn binding(id: &str) -> String {
    format!("mail:{id}")
}

/// Queued mail in every tenant of a region.
pub struct OutboxService {
    repository: Arc<dyn OutboxRepository>,
    tenancy: Tenancy,
}

impl OutboxService {
    pub(crate) fn new(repository: Arc<dyn OutboxRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Queue `mail` in `tenant`, sealed under `kek`, due now.
    ///
    /// # Errors
    ///
    /// A custody failure when sealing fails; store failures.
    pub async fn enqueue(&self, tenant: &TenantId, kek: &Kek, mail: &NewMail) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let id = token_id()?;
        let payload = Zeroizing::new(
            serde_json::to_vec(&Sealed {
                to: mail.to.as_ref().map(|to| to.as_str().to_owned()),
                subject: mail.subject.clone(),
                text: mail.text.clone(),
            })
            .map_err(|_| unreadable("the mail cannot be encoded"))?,
        );
        let sealed = base64url::encode(&kek.seal(tenant, &binding(&id), &payload)?);
        self.repository.enqueue(&place, &id, &sealed).await
    }

    /// Claim at most `count` of `tenant`'s mails that are due, opened under `kek`.
    ///
    /// # Errors
    ///
    /// A custody failure for a mail that does not open here; store failures.
    pub async fn claim(&self, tenant: &TenantId, kek: &Kek, count: u32) -> Result<Vec<QueuedMail>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .claim(&place, count)
            .await?
            .into_iter()
            .map(|claimed| opened(tenant, kek, claimed))
            .collect()
    }

    /// Release `tenant`'s mail `id` to be claimed again `after_secs` from now.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn retry(&self, tenant: &TenantId, id: &str, after_secs: u64) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let after_secs = i64::try_from(after_secs).map_err(|_| unreadable("a delay beyond i64"))?;
        self.repository.retry(&place, id, after_secs).await
    }

    /// Delete `tenant`'s mail `id`, once; `false` when there was none.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn finish(&self, tenant: &TenantId, id: &str) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        Ok(self.repository.finish(&place, id).await?.is_some())
    }
}

/// The mail a claimed row holds, opened under `kek`.
fn opened(tenant: &TenantId, kek: &Kek, claimed: ClaimedEntity) -> Result<QueuedMail> {
    let ClaimedEntity { spelled, mail } = claimed;
    let MailEntity { sealed, attempts } = mail;
    let id = answers::text_id(&spelled, "queued mail")?;
    let sealed = base64url::decode(&sealed).map_err(|_| unreadable("sealed"))?;
    let payload = kek.unseal(tenant, &binding(&id), &sealed)?;
    let Sealed { to, subject, text } =
        serde_json::from_slice(&payload).map_err(|_| unreadable("sealed"))?;
    Ok(QueuedMail {
        id,
        to: to
            .map(|to| EmailAddress::parse(&to))
            .transpose()
            .map_err(|_| unreadable("to"))?,
        subject,
        text,
        attempts: attempts
            .map(u32::try_from)
            .transpose()
            .map_err(|_| unreadable("attempts"))?
            .unwrap_or_default(),
    })
}
