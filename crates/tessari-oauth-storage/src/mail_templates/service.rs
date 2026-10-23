//! The wording of each mail as the rest of the server asks for it: a company's own override when it keeps a valid
//! one, else the region's default, else the wording the server ships with, so a missing or damaged row never stops a
//! mail. A company's wording is checked against its kind's rules before it is stored.

use std::sync::Arc;

use tessari_oauth_core::mail_template::{MailKind, Template, check};
use tessari_oauth_infrastructure::tessaridb::Place;
use tessari_oauth_types::{ErrorCategory, TenantId, Timestamp};

use super::TemplateEntity;
use super::model::{Reset, Set, Wording};
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
                revision: 0,
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

    /// Every kind with the wording `tenant` sends it with, its own or the default, and the revision a change names.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses, or holds a row the server cannot read.
    pub async fn wording(&self, tenant: &TenantId) -> Result<Vec<Wording>> {
        let place = self.tenancy.place(tenant)?;
        let own = kinded(self.repository.overrides(&place).await?, "mail template")?;
        let defaults = kinded(
            self.repository.defaults(self.tenancy.mail()).await?,
            "mail default",
        )?;
        MailKind::ALL
            .into_iter()
            .map(|kind| {
                let stored = own.iter().find(|(stored, _)| *stored == kind);
                let revision = match stored {
                    Some((_, entity)) => revision_of(entity.revision)?,
                    None => 0,
                };
                let own = stored.and_then(|(_, entity)| usable(kind, entity.clone()));
                let default = || {
                    defaults
                        .iter()
                        .find(|(stored, _)| *stored == kind)
                        .and_then(|(_, entity)| usable(kind, entity.clone()))
                        .unwrap_or_else(|| kind.built_in())
                };
                Ok(Wording {
                    kind,
                    own: own.is_some(),
                    template: own.unwrap_or_else(default),
                    revision,
                })
            })
            .collect()
    }

    /// Keep `template` as `tenant`'s wording for `kind`, set by `actor` at `now`, only over the revision `replaces` (0
    /// when the company keeps none); refused, storing nothing, when it breaks one of `kind`'s rules.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses.
    pub async fn set(
        &self,
        tenant: &TenantId,
        (kind, replaces): (MailKind, u64),
        template: &Template,
        actor: &str,
        now: Timestamp,
    ) -> Result<Set> {
        if let Err(refused) = check(kind, template) {
            return Ok(Set::Refused(refused));
        }
        let place = self.tenancy.place(tenant)?;
        let next = replaces.checked_add(1).ok_or(Error::Invalid {
            record: "mail template",
            reason: "a revision past the store's range",
        })?;
        let entity = TemplateEntity {
            spelled: String::new(),
            subject: template.subject.clone(),
            text: template.text.clone(),
            updated_at: seconds(now)?,
            updated_by: Some(actor.to_owned()),
            revision: stored_revision(next)?,
        };
        let made = if replaces == 0 {
            match self
                .repository
                .create_override(&place, kind.name(), &entity)
                .await
            {
                Ok(()) => true,
                // Set by somebody else since the operator read that there was none.
                Err(refused) if refused.category() == ErrorCategory::Conflict => false,
                Err(failure) => return Err(failure),
            }
        } else {
            let replaced = self
                .repository
                .replace_override(&place, kind.name(), stored_revision(replaces)?, &entity)
                .await;
            self.kept_or(&place, kind, replaced).await?
        };
        Ok(if made { Set::Made(next) } else { Set::Moved })
    }

    /// Send `kind` with the region's default wording again in `tenant`, only while the company's own is at
    /// `revision`.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses.
    pub async fn reset(&self, tenant: &TenantId, kind: MailKind, revision: u64) -> Result<Reset> {
        let place = self.tenancy.place(tenant)?;
        let removed = self
            .repository
            .delete_override(&place, kind.name(), stored_revision(revision)?)
            .await;
        if self.kept_or(&place, kind, removed).await? {
            return Ok(Reset::Made);
        }
        let kept = self.repository.find_override(&place, kind.name()).await?;
        Ok(if kept.is_some() {
            Reset::Moved
        } else {
            Reset::None
        })
    }

    /// A conditional write's outcome, where a refusal means only that the company's row is gone when it is: false
    /// then, as for a row at another revision; any other refusal stands.
    async fn kept_or(&self, place: &Place, kind: MailKind, written: Result<bool>) -> Result<bool> {
        match written {
            Ok(done) => Ok(done),
            Err(failure) => match self.repository.find_override(place, kind.name()).await? {
                None => Ok(false),
                Some(_) => Err(failure),
            },
        }
    }
}

/// Each of `entities` with the kind its id names.
fn kinded(
    entities: Vec<TemplateEntity>,
    record: &'static str,
) -> Result<Vec<(MailKind, TemplateEntity)>> {
    entities
        .into_iter()
        .map(|entity| {
            let id = answers::text_id(&entity.spelled, record)?;
            let kind = MailKind::parse(&id).ok_or_else(|| Error::Unreadable {
                record,
                reason: "an id that names no mail kind".to_owned(),
            })?;
            Ok((kind, entity))
        })
        .collect()
}

fn stored_revision(revision: u64) -> Result<i64> {
    i64::try_from(revision).map_err(|_| Error::Invalid {
        record: "mail template",
        reason: "a revision past the store's range",
    })
}

fn revision_of(stored: i64) -> Result<u64> {
    u64::try_from(stored).map_err(|_| Error::Unreadable {
        record: "mail template",
        reason: "a negative revision".to_owned(),
    })
}
