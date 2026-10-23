//! The wording of each mail as the rest of the server asks for it: a company's own override when it keeps a valid
//! one, else the region's default, else the wording the server ships with, so a missing or damaged row never stops a
//! mail. A company's wording is checked against its kind's rules before it is stored.

use std::sync::Arc;

use tessari_oauth_core::mail_template::{MailKind, Template, TemplateRefused, check};
use tessari_oauth_types::{ErrorCategory, TenantId, Timestamp};

use super::TemplateEntity;
use super::repository::MailTemplateRepository;
use crate::{Error, Result, Tenancy, answers};

/// Reads and sets the wording of the mail the server sends.
pub struct MailTemplateService {
    repository: Arc<dyn MailTemplateRepository>,
    tenancy: Tenancy,
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| Error::Invalid {
        record: "mail template",
        reason: "a time past the store's range",
    })
}

/// `entity` as `kind`'s wording, when it still passes `kind`'s rules.
fn usable(kind: MailKind, entity: TemplateEntity) -> Option<Template> {
    let template = Template {
        subject: entity.subject,
        text: entity.text,
    };
    check(kind, &template).is_ok().then_some(template)
}

impl MailTemplateService {
    pub(crate) fn new(repository: Arc<dyn MailTemplateRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Make the region's defaults exist, each from the shipped wording; a default already stored is kept as it is.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses a definition.
    pub async fn seed_defaults(&self, now: Timestamp) -> Result<()> {
        let place = self.tenancy.mail();
        self.repository.prepare(place).await?;
        for kind in MailKind::ALL {
            let shipped = kind.built_in();
            let entity = TemplateEntity {
                spelled: String::new(),
                subject: shipped.subject,
                text: shipped.text,
                updated_at: seconds(now)?,
                updated_by: None,
            };
            match self
                .repository
                .create_default(place, kind.name(), &entity)
                .await
            {
                Ok(()) => {}
                // CREATE never replaces: the default is there, as the region keeps it.
                Err(Error::Store(store))
                    if store.category() == ErrorCategory::Conflict && !store.is_retry() => {}
                Err(failure) => return Err(failure),
            }
        }
        Ok(())
    }

    /// The wording `tenant` sends `kind` with.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses.
    pub async fn resolve(&self, tenant: &TenantId, kind: MailKind) -> Result<Template> {
        let place = self.tenancy.place(tenant)?;
        let own = self
            .repository
            .find_override(&place, kind.name())
            .await?
            .and_then(|entity| usable(kind, entity));
        if let Some(template) = own {
            return Ok(template);
        }
        let default = self
            .repository
            .find_default(self.tenancy.mail(), kind.name())
            .await?;
        Ok(default
            .and_then(|entity| usable(kind, entity))
            .unwrap_or_else(|| kind.built_in()))
    }

    /// Every kind `tenant` keeps its own wording for.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses, or holds a row under an id that names no kind.
    pub async fn overrides(&self, tenant: &TenantId) -> Result<Vec<(MailKind, Template)>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .overrides(&place)
            .await?
            .into_iter()
            .map(|entity| {
                let id = answers::text_id(&entity.spelled, "mail template")?;
                let kind = MailKind::parse(&id).ok_or_else(|| Error::Unreadable {
                    record: "mail template",
                    reason: "an id that names no mail kind".to_owned(),
                })?;
                Ok((
                    kind,
                    Template {
                        subject: entity.subject,
                        text: entity.text,
                    },
                ))
            })
            .collect()
    }

    /// Keep `template` as `tenant`'s wording for `kind`, set by `actor` at `now`; refused, storing nothing, when it
    /// breaks one of `kind`'s rules.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses.
    pub async fn set(
        &self,
        tenant: &TenantId,
        kind: MailKind,
        template: &Template,
        actor: &str,
        now: Timestamp,
    ) -> Result<std::result::Result<(), TemplateRefused>> {
        if let Err(refused) = check(kind, template) {
            return Ok(Err(refused));
        }
        let place = self.tenancy.place(tenant)?;
        let entity = TemplateEntity {
            spelled: String::new(),
            subject: template.subject.clone(),
            text: template.text.clone(),
            updated_at: seconds(now)?,
            updated_by: Some(actor.to_owned()),
        };
        self.repository
            .put_override(&place, kind.name(), &entity)
            .await?;
        Ok(Ok(()))
    }

    /// Send `kind` with the region's default wording again in `tenant`; whether the company had its own.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses.
    pub async fn reset(&self, tenant: &TenantId, kind: MailKind) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        self.repository.delete_override(&place, kind.name()).await
    }
}
