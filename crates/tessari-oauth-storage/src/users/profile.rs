//! The profile an account's user keeps: three names, set and replaced whole from the account portal.

use tessari_oauth_constants::PROFILE_NAME_MAX_CHARS;
use tessari_oauth_types::{TenantId, UserId};

use super::{Profile, ProfileEntity, UserService};
use crate::{Error, Result};

/// `value` as kept: trimmed, `None` when nothing is left, refused when too long or holding a control character.
fn kept(value: Option<&String>) -> Result<Option<String>> {
    let Some(trimmed) = value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if trimmed.chars().count() > PROFILE_NAME_MAX_CHARS || trimmed.chars().any(char::is_control) {
        return Err(Error::Invalid {
            record: "profile",
            reason: "a name must be at most 100 characters with no control character",
        });
    }
    Ok(Some(trimmed.to_owned()))
}

impl UserService {
    /// The profile of `user` in `tenant`; `None` when there is no such account.
    ///
    /// # Errors
    ///
    /// The store's failures, and [`Error::Unreadable`] for a stored row of another shape.
    pub async fn profile(&self, tenant: &TenantId, user: &UserId) -> Result<Option<Profile>> {
        let place = self.tenancy.place(tenant)?;
        Ok(self
            .repository
            .find_profile(&place, user.as_str())
            .await?
            .map(|stored| Profile {
                name: stored.name,
                given_name: stored.given_name,
                family_name: stored.family_name,
            }))
    }

    /// Replace the profile of `user` in `tenant` with `profile`, each name trimmed and an empty one cleared; `false`
    /// when there is no such account.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for `profile` when a name is longer than the limit or holds a control character, with
    /// nothing written; the store's failures.
    pub async fn set_profile(
        &self,
        tenant: &TenantId,
        user: &UserId,
        profile: &Profile,
    ) -> Result<bool> {
        let place = self.tenancy.place(tenant)?;
        let stored = ProfileEntity {
            name: kept(profile.name.as_ref())?,
            given_name: kept(profile.given_name.as_ref())?,
            family_name: kept(profile.family_name.as_ref())?,
        };
        match self
            .repository
            .set_profile(&place, user.as_str(), &stored)
            .await
        {
            Ok(()) => Ok(true),
            // The store refuses an update of a record that is not there; only a missing account is answered `false`.
            Err(refusal @ Error::Store(tessari_oauth_infrastructure::Error::Refused { .. })) => {
                match self.repository.find_user(&place, user.as_str()).await? {
                    Some(_) => Err(refusal),
                    None => Ok(false),
                }
            }
            Err(failure) => Err(failure),
        }
    }
}
