//! Re-sealing: every value of a company sealed under one key-encryption key, sealed again under another, each under
//! the label its own family binds it to.

use std::sync::Arc;

use tessari_oauth_constants::RESEAL_PAGE;
use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_types::{TenantId, UserId, base64url};

use super::Resealed;
use super::model::Family;
use super::repository::SealedRepository;
use crate::factors::{pending_totp_binding, totp_binding};
use crate::outbox::mail_binding;
use crate::{Error, Result, Tenancy, answers};

/// What a probe that tells two keys apart is sealed for; no stored value is bound to it.
const PROBE_LABEL: &str = "reseal-probe";

/// What to do with one sealed value.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// It opens under the new key.
    Already,
    /// It opened under the old key; this is it sealed under the new one, base64url.
    Reseal(String),
    /// It opens under neither, or is not a sealed value.
    Unopened,
}

/// Sealing every value of a company again under a new key-encryption key.
#[derive(Clone)]
pub struct SealedService {
    repository: Arc<dyn SealedRepository>,
    tenancy: Tenancy,
}

/// The label a value of `family` stored under `id` is sealed for, read from the family's own binding; `None` when the
/// record does not carry what its binding needs.
fn label(family: Family, id: &str, user_id: Option<&str>) -> Option<String> {
    match family {
        Family::SigningKeys | Family::Secrets => Some(id.to_owned()),
        Family::MailOutbox => Some(mail_binding(id)),
        Family::TotpFactors => UserId::parse(id).ok().map(|user| totp_binding(&user)),
        Family::TotpPending => user_id
            .and_then(|user| UserId::parse(user).ok())
            .map(|user| pending_totp_binding(&user)),
    }
}

/// Whether `old` opens what `new` seals: then they are one key and a re-seal would change nothing.
fn same_key(tenant: &TenantId, old: &Kek, new: &Kek) -> Result<bool> {
    let probe = new.seal(tenant, PROBE_LABEL, PROBE_LABEL.as_bytes())?;
    Ok(old.unseal(tenant, PROBE_LABEL, &probe).is_ok())
}

/// The new key is tried first, so a run that stopped part way and is run again writes only what is left.
fn decide(tenant: &TenantId, label: &str, sealed: &str, old: &Kek, new: &Kek) -> Result<Outcome> {
    let Ok(bytes) = base64url::decode(sealed) else {
        return Ok(Outcome::Unopened);
    };
    if new.unseal(tenant, label, &bytes).is_ok() {
        return Ok(Outcome::Already);
    }
    let Ok(plaintext) = old.unseal(tenant, label, &bytes) else {
        return Ok(Outcome::Unopened);
    };
    Ok(Outcome::Reseal(base64url::encode(
        &new.seal(tenant, label, &plaintext)?,
    )))
}

impl SealedService {
    pub(crate) fn new(repository: Arc<dyn SealedRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Seal every value `tenant` holds under `old` again under `new`, family by family, and count what was found.
    /// Run it with every node stopped: a node still serving seals new values under the old key.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `old` and `new` are the same key; a custody failure sealing; the store's refusal of a
    /// value that changed between its read and its write; and the store's other failures.
    pub async fn reseal(&self, tenant: &TenantId, old: &Kek, new: &Kek) -> Result<Resealed> {
        if same_key(tenant, old, new)? {
            return Err(Error::Invalid {
                record: "key-encryption key",
                reason: "the old and the new key are the same key",
            });
        }
        let place = self.tenancy.place(tenant)?;
        let mut found = Resealed::default();
        for family in Family::ALL {
            let mut after: Option<String> = None;
            loop {
                let page = self
                    .repository
                    .page(&place, family, after.as_deref(), RESEAL_PAGE)
                    .await?;
                let Some(last) = page.last() else {
                    break;
                };
                after = Some(answers::text_id(&last.spelled, "sealed value")?);
                for row in page {
                    let id = answers::text_id(&row.spelled, "sealed value")?;
                    let outcome = match label(family, &id, row.user_id.as_deref()) {
                        Some(label) => decide(tenant, &label, &row.sealed, old, new)?,
                        None => Outcome::Unopened,
                    };
                    match outcome {
                        Outcome::Already => found.already = found.already.saturating_add(1),
                        Outcome::Unopened => found.unopened = found.unopened.saturating_add(1),
                        Outcome::Reseal(sealed) => {
                            self.repository
                                .replace(&place, family, &id, &row.sealed, &sealed)
                                .await?;
                            found.resealed = found.resealed.saturating_add(1);
                        }
                    }
                }
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
