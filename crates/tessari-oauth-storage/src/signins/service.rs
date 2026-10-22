//! The sign-in service: one browser's sign-in in progress, found only by that browser, moved on one step at a time
//! and finished once.
//!
//! The record's id is the digest of the value in the browser's sign-in cookie, so a request from any other browser
//! finds nothing at all. A step is written only over the revision it was taken from, so of two steps taken from the
//! same place (a resent form, two tabs) one is kept and the other is told it is stale. What is kept is rebuilt
//! through the ceremony's own transitions when it is read, so a record no step could have produced is refused, and a
//! sign-in older than an authorization request's lifetime is no longer found, by this server's clock as well as the
//! store's.

use std::sync::Arc;

use tessari_oauth_constants::{INTERACTION_TTL_SECS, SIGNIN_WRITE_ATTEMPTS};
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::ceremony::{Ceremony, Identity};
use tessari_oauth_types::{ErrorCategory, SigninBinding, TenantId, Timestamp, UserId};

use super::repository::SigninRepository;
use super::{Signin, SigninEntity};
use crate::{Error, Result, Tenancy, retry};

/// Sign-ins in progress.
#[derive(Clone)]
pub struct SigninService {
    repository: Arc<dyn SigninRepository>,
    tenancy: Tenancy,
}

fn unreadable(reason: &str) -> Error {
    Error::Unreadable {
        record: "sign-in",
        reason: reason.to_owned(),
    }
}

/// The row `ceremony` is kept as, at `revision`, for `interaction`, begun at `created_at`.
fn kept(
    ceremony: &Ceremony,
    account: Option<&str>,
    interaction: &str,
    revision: i64,
    created_at: i64,
) -> SigninEntity {
    let (identified, user_id, second_factor) = match ceremony.identity() {
        None => (false, None, false),
        Some(Identity::Unknown) => (true, None, false),
        Some(Identity::Known {
            user,
            second_factor,
        }) => (true, Some(user.as_str().to_owned()), *second_factor),
    };
    SigninEntity {
        interaction: interaction.to_owned(),
        identified,
        user_id,
        second_factor,
        account: account.map(str::to_owned),
        methods: ceremony
            .verified_methods()
            .iter()
            .map(|method| method.name().to_owned())
            .collect(),
        revision,
        created_at,
    }
}

/// The sign-in a row holds, unless it began an authorization request's lifetime or more before `now`.
fn held(row: SigninEntity, now: Timestamp) -> Result<Option<Signin>> {
    let lifetime = i64::try_from(INTERACTION_TTL_SECS).map_err(|_| unreadable("lifetime"))?;
    let lapses_at = row
        .created_at
        .checked_add(lifetime)
        .ok_or_else(|| unreadable("created_at"))?;
    let now = i64::try_from(now.unix_secs()).map_err(|_| unreadable("now"))?;
    if now >= lapses_at {
        return Ok(None);
    }
    let identity = match (row.identified, row.user_id) {
        (false, None) => None,
        (false, Some(_)) => return Err(unreadable("user_id")),
        (true, None) => Some(Identity::Unknown),
        (true, Some(user)) => Some(Identity::Known {
            user: UserId::parse(user).map_err(|_| unreadable("user_id"))?,
            second_factor: row.second_factor,
        }),
    };
    let methods = row
        .methods
        .iter()
        .map(|name| Method::named(name).ok_or_else(|| unreadable("methods")))
        .collect::<Result<Vec<_>>>()?;
    let ceremony = Ceremony::resume(identity, methods).map_err(|_| unreadable("progress"))?;
    Ok(Some(Signin {
        interaction: row.interaction,
        ceremony,
        account: row.account,
        revision: row.revision,
    }))
}

impl SigninService {
    pub(crate) fn new(repository: Arc<dyn SigninRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Begin a sign-in for the pending authorization `interaction` in `tenant`, bound to the browser holding
    /// `binding`, at `now`; `false` when that browser already has one.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn begin(
        &self,
        tenant: &TenantId,
        binding: &SigninBinding,
        interaction: &str,
        now: Timestamp,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let id = binding.digest();
        let created_at = i64::try_from(now.unix_secs()).map_err(|_| unreadable("now"))?;
        let row = kept(&Ceremony::new(), None, interaction, 0, created_at);
        let created = retry::bounded(SIGNIN_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.create(&place, &id, &row)
        })
        .await;
        match created {
            Ok(()) => Ok(true),
            // The browser already has a sign-in under this cookie; it keeps the one it has.
            Err(Error::Store(store))
                if store.category() == ErrorCategory::Conflict && !store.is_retry() =>
            {
                Ok(false)
            }
            Err(failure) => Err(failure),
        }
    }

    /// The sign-in the browser holding `binding` has in progress in `tenant` at `now`, when there is one.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record no step could have produced.
    pub async fn resume(
        &self,
        tenant: &TenantId,
        binding: &SigninBinding,
        now: Timestamp,
    ) -> Result<Option<Signin>> {
        let place = self.tenancy.place(tenant)?;
        match self.repository.find(&place, &binding.digest()).await? {
            Some(row) => held(row, now),
            None => Ok(None),
        }
    }

    /// Write `ceremony`, counted under `account`, as the next step of the browser's sign-in, taken from `revision`;
    /// `false` when the sign-in has moved on since, or is gone.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn advance(
        &self,
        tenant: &TenantId,
        binding: &SigninBinding,
        revision: i64,
        ceremony: &Ceremony,
        account: Option<&str>,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let id = binding.digest();
        let next = revision
            .checked_add(1)
            .ok_or_else(|| unreadable("revision"))?;
        // The interaction and the start are not rewritten; the update names only the progress fields.
        let row = kept(ceremony, account, "", next, 0);
        let advanced = retry::bounded(SIGNIN_WRITE_ATTEMPTS, retry::on_store_retry, || {
            self.repository.advance(&place, &id, revision, &row)
        })
        .await;
        match advanced {
            Ok(()) => Ok(true),
            // Only the store saying no is answered by looking again; the kept revision says why it said no.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                match self.repository.find(&place, &id).await? {
                    Some(current) if current.revision == revision => Err(refusal),
                    _ => Ok(false),
                }
            }
            Err(failure) => Err(failure),
        }
    }

    /// Finish the browser's sign-in at `now`, once: what it held, when it was there and in time.
    ///
    /// # Errors
    ///
    /// Store failures, and [`Error::Unreadable`] for a record no step could have produced.
    pub async fn finish(
        &self,
        tenant: &TenantId,
        binding: &SigninBinding,
        now: Timestamp,
    ) -> Result<Option<Signin>> {
        let place = self.tenancy.place(tenant)?;
        let id = binding.digest();
        let taken = retry::take_once(
            SIGNIN_WRITE_ATTEMPTS,
            || self.repository.take(&place, &id),
            || async { Ok(self.repository.find(&place, &id).await?.is_some()) },
        )
        .await?;
        match taken {
            Some(row) => held(row, now),
            None => Ok(None),
        }
    }
}
