//! The company service: the directory's only writer. A company is created in `provisioning`, made `active` once its
//! storage and keys exist, and may be suspended and resumed; each move is a compare-and-set on the status it leaves.

use std::sync::Arc;

use tessari_oauth_constants::{COMPANY_NAME_MAX_CHARS, COMPANY_PAGE_MAX};
use tessari_oauth_types::{ErrorCategory, TenantId, Timestamp};

use super::entity::ListedEntity;
use super::repository::CompanyRepository;
use super::{Company, CompanyEntity, CompanyStatus, Created};
use crate::{Error, Result, Tenancy, answers};

/// The directory of a region's companies.
pub struct CompanyService {
    repository: Arc<dyn CompanyRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "company",
        reason: reason.to_owned(),
    }
}

/// Whether `failure` is the store saying the state assumed is not the state there is.
fn is_conflict(failure: &Error) -> bool {
    matches!(failure, Error::Store(store) if store.category() == ErrorCategory::Conflict && !store.is_retry())
}

impl CompanyService {
    pub(crate) fn new(repository: Arc<dyn CompanyRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Make the directory exist; running it again changes nothing.
    ///
    /// # Errors
    ///
    /// When the store is unavailable or refuses a definition.
    pub async fn prepare(&self) -> Result<()> {
        self.repository.prepare(self.tenancy.directory()).await
    }

    /// Create the company `id` called `name`, in `provisioning`, recorded as created by `by` at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a name that is empty, longer than the limit or holds a control character; store
    /// failures. An id that is taken is [`Created::Taken`], not an error.
    pub async fn create(
        &self,
        id: &TenantId,
        name: &str,
        by: &str,
        now: Timestamp,
    ) -> Result<Created> {
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > COMPANY_NAME_MAX_CHARS
            || name.chars().any(char::is_control)
        {
            return Err(Error::Invalid {
                record: "company",
                reason: "a name must be 1 to 100 characters with no control character",
            });
        }
        let created_at = i64::try_from(now.unix_secs()).map_err(|_| Error::Invalid {
            record: "company",
            reason: "a creation time past the store's range",
        })?;
        let company = CompanyEntity {
            name: name.to_owned(),
            status: CompanyStatus::Provisioning.name().to_owned(),
            created_at,
            created_by: by.to_owned(),
        };
        match self
            .repository
            .create(self.tenancy.directory(), id.as_str(), &company)
            .await
        {
            Ok(()) => Ok(Created::Created),
            Err(failure) if is_conflict(&failure) => Ok(Created::Taken),
            Err(failure) => Err(failure),
        }
    }

    /// The company `id`, whatever its status.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn find(&self, id: &TenantId) -> Result<Option<Company>> {
        self.repository
            .find(self.tenancy.directory(), id.as_str())
            .await?
            .map(|entity| company(id.clone(), entity))
            .transpose()
    }

    /// At most `count` companies (never more than the page limit) in id order, after `after` when it is given.
    ///
    /// # Errors
    ///
    /// Store failures, among them the refusal of an anchor the directory does not hold, and [`Error::Unreadable`].
    pub async fn page(&self, after: Option<&TenantId>, count: u32) -> Result<Vec<Company>> {
        self.repository
            .page(
                self.tenancy.directory(),
                after.map(TenantId::as_str),
                count.min(COMPANY_PAGE_MAX),
            )
            .await?
            .into_iter()
            .map(
                |ListedEntity {
                     spelled,
                     company: entity,
                 }| {
                    let id = TenantId::parse(answers::text_id(&spelled, "company")?)
                        .map_err(|_| unreadable("id"))?;
                    company(id, entity)
                },
            )
            .collect()
    }

    /// Move the company `id` from `from` to `to`; `false` when it was not in `from`, or does not exist.
    ///
    /// # Errors
    ///
    /// Store failures other than that refusal.
    pub async fn transition(
        &self,
        id: &TenantId,
        from: CompanyStatus,
        to: CompanyStatus,
    ) -> Result<bool> {
        match self
            .repository
            .transition(
                self.tenancy.directory(),
                id.as_str(),
                from.name(),
                to.name(),
            )
            .await
        {
            Ok(()) => Ok(true),
            Err(failure) if is_conflict(&failure) => Ok(false),
            Err(failure) => Err(failure),
        }
    }
}

/// The company a stored row holds.
fn company(id: TenantId, entity: CompanyEntity) -> Result<Company> {
    let CompanyEntity {
        name,
        status,
        created_at,
        created_by,
    } = entity;
    Ok(Company {
        id,
        name,
        status: CompanyStatus::parse(&status).ok_or_else(|| unreadable("status"))?,
        created_at: Timestamp::from_unix_secs(
            u64::try_from(created_at).map_err(|_| unreadable("created_at"))?,
        ),
        created_by,
    })
}
