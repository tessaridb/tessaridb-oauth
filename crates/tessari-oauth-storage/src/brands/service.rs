//! A company's brand and logo as the rest of the server asks for them: every stored value is read back through the
//! same typed parse that admitted it, so a record edited behind the server's back is refused rather than served.

use std::sync::Arc;

use tessari_oauth_core::branding::{Accent, BrandLink, BrandName};
use tessari_oauth_core::logo::Png;
use tessari_oauth_types::{ErrorCategory, TenantId, Timestamp, base64url};

use super::repository::BrandRepository;
use super::{BrandEntity, LogoEntity};
use crate::{Error, Result, Tenancy};

/// A company's brand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brand {
    /// The display name.
    pub name: BrandName,
    /// The accent colour.
    pub accent: Accent,
    /// The support link, when one is set.
    pub support: Option<BrandLink>,
    /// The privacy link, when one is set.
    pub privacy: Option<BrandLink>,
    /// When it was last set.
    pub updated_at: Timestamp,
}

/// A company's brand as read, with the revision a change to it must name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revised {
    /// The brand.
    pub brand: Brand,
    /// How many times it was set: 1 for the first.
    pub revision: u64,
}

/// Reads and sets each company's brand and logo.
pub struct BrandService {
    repository: Arc<dyn BrandRepository>,
    tenancy: Tenancy,
}

fn unreadable(record: &'static str, reason: &str) -> Error {
    Error::Unreadable {
        record,
        reason: reason.to_owned(),
    }
}

fn seconds(at: Timestamp) -> Result<i64> {
    i64::try_from(at.unix_secs()).map_err(|_| Error::Invalid {
        record: "brand",
        reason: "a time past the store's range",
    })
}

fn stored_revision(revision: u64) -> Result<i64> {
    i64::try_from(revision).map_err(|_| Error::Invalid {
        record: "brand",
        reason: "a revision past the store's range",
    })
}

fn instant(stored: i64, record: &'static str) -> Result<Timestamp> {
    u64::try_from(stored)
        .map(Timestamp::from_unix_secs)
        .map_err(|_| unreadable(record, "a time before 1970"))
}

fn link(stored: Option<String>) -> Result<Option<BrandLink>> {
    stored
        .map(|raw| {
            BrandLink::parse(&raw).map_err(|_| unreadable("brand", "a link the brand rules refuse"))
        })
        .transpose()
}

fn to_revised(entity: BrandEntity) -> Result<Revised> {
    let brand = Brand {
        name: BrandName::parse(&entity.name)
            .map_err(|_| unreadable("brand", "a name the brand rules refuse"))?,
        accent: Accent::parse(&entity.accent)
            .map_err(|_| unreadable("brand", "a colour the brand rules refuse"))?,
        support: link(entity.support_url)?,
        privacy: link(entity.privacy_url)?,
        updated_at: instant(entity.updated_at, "brand")?,
    };
    let revision = u64::try_from(entity.revision)
        .ok()
        .filter(|revision| *revision > 0)
        .ok_or_else(|| unreadable("brand", "a revision below 1"))?;
    Ok(Revised { brand, revision })
}

impl BrandService {
    pub(crate) fn new(repository: Arc<dyn BrandRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// `tenant`'s brand and its revision, when one is set.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored value the brand rules refuse.
    pub async fn find(&self, tenant: &TenantId) -> Result<Option<Revised>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .find(&place)
            .await?
            .map(to_revised)
            .transpose()
    }

    /// Set `tenant`'s brand to `brand` whole, a link it leaves out removed, only over the revision `replaces` (0 when
    /// none is set); whether it was set, false when the brand moved since that revision was read.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn set(&self, tenant: &TenantId, replaces: u64, brand: &Brand) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let next = replaces.checked_add(1).ok_or(Error::Invalid {
            record: "brand",
            reason: "a revision past the store's range",
        })?;
        let entity = BrandEntity {
            name: brand.name.as_str().to_owned(),
            accent: brand.accent.as_str().to_owned(),
            support_url: brand.support.as_ref().map(|link| link.as_str().to_owned()),
            privacy_url: brand.privacy.as_ref().map(|link| link.as_str().to_owned()),
            updated_at: seconds(brand.updated_at)?,
            revision: stored_revision(next)?,
        };
        let written = if replaces == 0 {
            self.repository.create(&place, &entity).await
        } else {
            self.repository
                .replace(&place, stored_revision(replaces)?, &entity)
                .await
        };
        match written {
            Ok(()) => Ok(true),
            // Set or changed by somebody else since the revision was read.
            Err(refused) if refused.category() == ErrorCategory::Conflict => Ok(false),
            Err(failure) => Err(failure),
        }
    }

    /// `tenant`'s logo, the PNG bytes this server wrote, when one is set.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored logo that is not base64url.
    pub async fn logo(&self, tenant: &TenantId) -> Result<Option<Vec<u8>>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .find_logo(&place)
            .await?
            .map(|stored| {
                base64url::decode(&stored.png)
                    .map_err(|_| unreadable("brand logo", "an image that is not base64url"))
            })
            .transpose()
    }

    /// When `tenant`'s logo was uploaded, read without the image; none without a logo.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn logo_updated(&self, tenant: &TenantId) -> Result<Option<Timestamp>> {
        let place = self.tenancy.place(tenant)?;
        self.repository
            .logo_stamp(&place)
            .await?
            .map(|stamp| instant(stamp.updated_at, "brand logo"))
            .transpose()
    }

    /// Set `tenant`'s logo to `png`, uploaded `at`.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn set_logo(&self, tenant: &TenantId, png: &Png, at: Timestamp) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        let entity = LogoEntity {
            png: base64url::encode(png.as_bytes()),
            updated_at: seconds(at)?,
        };
        self.repository.put_logo(&place, &entity).await
    }

    /// Remove `tenant`'s logo; whether there was one.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn remove_logo(&self, tenant: &TenantId) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        self.repository.delete_logo(&place).await
    }
}
