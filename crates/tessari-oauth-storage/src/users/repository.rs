//! What the user service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::{CredentialEntity, EmailEntity, ProfileEntity, UserEntity};
use crate::Result;

/// The accounts, their addresses and their credentials.
#[async_trait]
pub(crate) trait UserRepository: Send + Sync {
    /// Write `user` and `email` together, refused — with neither written — when the address is taken.
    async fn create(&self, place: &Place, user: &UserEntity, email: &EmailEntity) -> Result<()>;

    /// The record of `address`, when there is one.
    async fn find_email(&self, place: &Place, address: &str) -> Result<Option<EmailEntity>>;

    /// The account `user_id`, when there is one.
    async fn find_user(&self, place: &Place, user_id: &str) -> Result<Option<UserEntity>>;

    /// The address `user_id` signs in with, when the account has one.
    async fn find_email_of(&self, place: &Place, user_id: &str) -> Result<Option<EmailEntity>>;

    /// Write `credential` whole, replacing any before it.
    async fn put_credential(&self, place: &Place, credential: &CredentialEntity) -> Result<()>;

    /// The credential of `user_id`, when there is one.
    async fn find_credential(
        &self,
        place: &Place,
        user_id: &str,
    ) -> Result<Option<CredentialEntity>>;

    /// At most `count` accounts after the account `after`, in id order.
    async fn page(&self, place: &Place, after: Option<&str>, count: u32)
    -> Result<Vec<UserEntity>>;

    /// The addresses of the accounts `user_ids`.
    async fn emails_of(&self, place: &Place, user_ids: &[String]) -> Result<Vec<EmailEntity>>;

    /// Move the account `user_id` from status `from` to `to`, refused unless it is in `from`.
    async fn set_status(&self, place: &Place, user_id: &str, from: &str, to: &str) -> Result<()>;

    /// The profile names on `user_id`'s account; `None` when there is no such account.
    async fn find_profile(&self, place: &Place, user_id: &str) -> Result<Option<ProfileEntity>>;

    /// Replace the profile names on `user_id`'s account; `false` when there is no such account.
    async fn set_profile(
        &self,
        place: &Place,
        user_id: &str,
        profile: &ProfileEntity,
    ) -> Result<()>;
}
