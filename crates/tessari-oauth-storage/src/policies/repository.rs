//! What the policy service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::{PolicyEntity, RegistrationEntity};
use crate::Result;

/// Reads and writes a company's policies.
#[async_trait]
pub(crate) trait PolicyRepository: Send + Sync {
    /// The stored two-factor policy, when one was ever set.
    async fn find_two_factor(&self, place: &Place) -> Result<Option<PolicyEntity>>;

    /// Store `policy` as the two-factor policy, replacing any before.
    async fn put_two_factor(&self, place: &Place, policy: &str) -> Result<()>;

    /// Store `policy` as the first two-factor policy, refused when one was stored meanwhile.
    async fn create_two_factor(&self, place: &Place, policy: &str) -> Result<()>;

    /// Store `policy` as the two-factor policy, refused unless the stored one is still `expected`.
    async fn replace_two_factor(&self, place: &Place, expected: &str, policy: &str) -> Result<()>;

    /// The stored registration policy, when one was ever kept.
    async fn find_registration(&self, place: &Place) -> Result<Option<RegistrationEntity>>;

    /// Keep `policy` as the first registration policy, refused when one was kept meanwhile.
    async fn create_registration(&self, place: &Place, policy: &RegistrationEntity) -> Result<()>;

    /// Keep `policy`, whose revision follows `replaces`; refused unless the kept one is still at `replaces`.
    async fn replace_registration(
        &self,
        place: &Place,
        replaces: i64,
        policy: &RegistrationEntity,
    ) -> Result<()>;
}
