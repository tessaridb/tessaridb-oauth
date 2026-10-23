//! The user service: register an account under the address it signs in with, find it by that address, and keep its
//! password credential.
//!
//! An account's id is random (128 bits from the system's random source) and is never an address or a name, so a
//! changed or recycled address never carries an account with it. An address belongs to one account in its tenant:
//! the store refuses a second record under it, and a registration that meets that refusal writes nothing and says the
//! address is taken — whether the caller may tell anyone so is decided where the answer is made, not here. A stored
//! record that no longer reads as an account is an error, never an account, so a sign-in fails closed.

use std::sync::Arc;

use tessari_oauth_constants::USER_PAGE_MAX;
use tessari_oauth_infrastructure::custody::token_id;
use tessari_oauth_types::{EmailAddress, ErrorCategory, TenantId, Timestamp, UserId};

use super::repository::UserRepository;
use super::{
    CredentialEntity, EmailEntity, Registered, StoredPassword, UserAccount, UserEntity, UserStatus,
};
use crate::{Error, Result, Tenancy};

/// Accounts and their credentials.
#[derive(Clone)]
pub struct UserService {
    pub(super) repository: Arc<dyn UserRepository>,
    pub(super) tenancy: Tenancy,
}

fn unreadable(record: &'static str, reason: &str) -> Error {
    Error::Unreadable {
        record,
        reason: reason.to_owned(),
    }
}

fn status_from(name: &str) -> Result<UserStatus> {
    [UserStatus::Active, UserStatus::Disabled]
        .into_iter()
        .find(|status| status.name() == name)
        .ok_or_else(|| unreadable("user", "a status this server does not know"))
}

impl UserService {
    pub(crate) fn new(repository: Arc<dyn UserRepository>, tenancy: Tenancy) -> Self {
        Self {
            repository,
            tenancy,
        }
    }

    /// Register a new active account signing in with `email` in `tenant` at `now`.
    ///
    /// # Errors
    ///
    /// The store's failures, contention among them, which a caller may retry.
    pub async fn register(
        &self,
        tenant: &TenantId,
        email: &EmailAddress,
        now: Timestamp,
    ) -> Result<Registered> {
        let place = self.tenancy.place(tenant)?;
        let user = UserId::parse(token_id()?).map_err(|_| Error::Invalid {
            record: "user",
            reason: "a generated id outside the user id grammar",
        })?;
        let created_at = i64::try_from(now.unix_secs()).map_err(|_| Error::Invalid {
            record: "user",
            reason: "a registration time past the store's range",
        })?;
        let account = UserEntity {
            user_id: user.as_str().to_owned(),
            tenant: tenant.as_str().to_owned(),
            status: UserStatus::Active.name().to_owned(),
            created_at,
        };
        let address = EmailEntity {
            address: email.as_str().to_owned(),
            user_id: user.as_str().to_owned(),
            verified_at: None,
            verified_by: None,
        };
        match self.repository.create(&place, &account, &address).await {
            Ok(()) => Ok(Registered::Created(user)),
            // A conflict that is not contention is the address record already standing.
            Err(Error::Store(store))
                if store.category() == ErrorCategory::Conflict && !store.is_retry() =>
            {
                Ok(Registered::AddressTaken)
            }
            Err(failure) => Err(failure),
        }
    }

    /// The account signing in with `email` in `tenant`, when there is one.
    ///
    /// # Errors
    ///
    /// The store's failures, and [`Error::Unreadable`] for a stored record of another shape or an address naming
    /// no account.
    pub async fn find_by_email(
        &self,
        tenant: &TenantId,
        email: &EmailAddress,
    ) -> Result<Option<UserAccount>> {
        let place = self.tenancy.place(tenant)?;
        let Some(address) = self.repository.find_email(&place, email.as_str()).await? else {
            return Ok(None);
        };
        let account = self
            .repository
            .find_user(&place, &address.user_id)
            .await?
            .ok_or_else(|| unreadable("user email", "an address naming no account"))?;
        account_of(&address, account).map(Some)
    }

    /// The account `user` of `tenant` with the address it signs in with, when there is one.
    ///
    /// # Errors
    ///
    /// The store's failures, and [`Error::Unreadable`] for a stored record of another shape or an account with no
    /// address.
    pub async fn find(&self, tenant: &TenantId, user: &UserId) -> Result<Option<UserAccount>> {
        let place = self.tenancy.place(tenant)?;
        let Some(account) = self.repository.find_user(&place, user.as_str()).await? else {
            return Ok(None);
        };
        let address = self
            .repository
            .find_email_of(&place, user.as_str())
            .await?
            .ok_or_else(|| unreadable("user", "an account with no address"))?;
        account_of(&address, account).map(Some)
    }

    /// Store `password` for `user` of `tenant` at `now`, replacing the one before. Accounts are never removed, so
    /// one found here is still there when the credential lands.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for `credential` when there is no such account; the store's failures.
    pub async fn set_password(
        &self,
        tenant: &TenantId,
        user: &UserId,
        password: &StoredPassword,
        now: Timestamp,
    ) -> Result<()> {
        let place = self.tenancy.place(tenant)?;
        if self
            .repository
            .find_user(&place, user.as_str())
            .await?
            .is_none()
        {
            return Err(Error::Invalid {
                record: "credential",
                reason: "there is no such account",
            });
        }
        let updated_at = i64::try_from(now.unix_secs()).map_err(|_| Error::Invalid {
            record: "credential",
            reason: "a time past the store's range",
        })?;
        let credential = CredentialEntity {
            user_id: user.as_str().to_owned(),
            hash: password.hash.clone(),
            pepper: i64::from(password.pepper),
            updated_at,
        };
        self.repository.put_credential(&place, &credential).await
    }

    /// The password credential of `user` of `tenant`, when there is one.
    ///
    /// # Errors
    ///
    /// The store's failures, and [`Error::Unreadable`] for a stored record of another shape.
    pub async fn password(
        &self,
        tenant: &TenantId,
        user: &UserId,
    ) -> Result<Option<StoredPassword>> {
        let place = self.tenancy.place(tenant)?;
        let Some(credential) = self
            .repository
            .find_credential(&place, user.as_str())
            .await?
        else {
            return Ok(None);
        };
        Ok(Some(StoredPassword {
            hash: credential.hash,
            pepper: u32::try_from(credential.pepper)
                .map_err(|_| unreadable("credential", "a pepper version out of range"))?,
        }))
    }
    /// At most `count` accounts of `tenant`, never more than [`USER_PAGE_MAX`], after the account `after` in id order,
    /// each with the address it signs in with.
    ///
    /// # Errors
    ///
    /// Store failures, among them the refusal of an anchor the company does not hold, and [`Error::Unreadable`].
    pub async fn page(
        &self,
        tenant: &TenantId,
        after: Option<&UserId>,
        count: u32,
    ) -> Result<Vec<UserAccount>> {
        let place = self.tenancy.place(tenant)?;
        let accounts = self
            .repository
            .page(&place, after.map(UserId::as_str), count.min(USER_PAGE_MAX))
            .await?;
        if accounts.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<String> = accounts
            .iter()
            .map(|account| account.user_id.clone())
            .collect();
        let addresses: std::collections::HashMap<String, EmailEntity> = self
            .repository
            .emails_of(&place, &ids)
            .await?
            .into_iter()
            .map(|address| (address.user_id.clone(), address))
            .collect();
        accounts
            .into_iter()
            .map(|account| {
                let address = addresses
                    .get(&account.user_id)
                    .ok_or_else(|| unreadable("user", "an account with no address"))?;
                account_of(address, account)
            })
            .collect()
    }

    /// Move `user` of `tenant` from status `from` to `to`; `false`, changing nothing, when the account is not in `from`
    /// (already moved, or no such account).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub async fn set_status(
        &self,
        tenant: &TenantId,
        user: &UserId,
        from: UserStatus,
        to: UserStatus,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        match self
            .repository
            .set_status(&place, user.as_str(), from.name(), to.name())
            .await
        {
            Ok(()) => Ok(true),
            // Not in `from` any more, or never there: the store refuses both as a conflict, and nothing changed.
            Err(refused) if refused.category() == ErrorCategory::Conflict => Ok(false),
            Err(failure) => Err(failure),
        }
    }
}

/// The account `account` signing in with `address`, as the service hands it out.
fn account_of(address: &EmailEntity, account: UserEntity) -> Result<UserAccount> {
    Ok(UserAccount {
        user: UserId::parse(account.user_id)
            .map_err(|_| unreadable("user", "an id outside the grammar"))?,
        email: EmailAddress::parse(&address.address)
            .map_err(|_| unreadable("user email", "not an address"))?,
        email_verified: address.verified_at.is_some(),
        status: status_from(&account.status)?,
    })
}
