//! What the sign-in service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::SigninEntity;
use crate::Result;

/// Sign-ins in progress.
#[async_trait]
pub(crate) trait SigninRepository: Send + Sync {
    /// Write `signin` under `id`, refused when one exists.
    async fn create(&self, place: &Place, id: &str, signin: &SigninEntity) -> Result<()>;

    /// The sign-in under `id`, when there is one.
    async fn find(&self, place: &Place, id: &str) -> Result<Option<SigninEntity>>;

    /// Write `signin`'s progress under `id` while its revision is still `revision`; refused otherwise.
    async fn advance(
        &self,
        place: &Place,
        id: &str,
        revision: i64,
        signin: &SigninEntity,
    ) -> Result<()>;

    /// Delete the sign-in under `id`, answering what it held when there was one.
    async fn take(&self, place: &Place, id: &str) -> Result<Option<SigninEntity>>;
}
