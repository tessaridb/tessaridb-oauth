//! What the group service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::{GroupEntity, MembershipEntity};
use crate::Result;

/// Groups and memberships.
#[async_trait]
pub(crate) trait GroupRepository: Send + Sync {
    /// Record `entity` as a new group; a group already under its id is a conflict.
    async fn create(&self, place: &Place, entity: &GroupEntity) -> Result<()>;

    /// The group under `id`, if any.
    async fn find(&self, place: &Place, id: &str) -> Result<Option<GroupEntity>>;

    /// The groups under `ids` that stand, in id order.
    async fn find_many(&self, place: &Place, ids: &[String]) -> Result<Vec<GroupEntity>>;

    /// At most `count` groups after the group `after`, in id order.
    async fn page(
        &self,
        place: &Place,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<GroupEntity>>;

    /// Set the roles of the group `id`; a group that is not there refuses, with nothing written.
    async fn set_roles(&self, place: &Place, id: &str, roles: &[String]) -> Result<()>;

    /// Delete the group `id` and every membership of it in one transaction.
    async fn delete(&self, place: &Place, id: &str) -> Result<()>;

    /// Record `entity` under its id, only while its group stands; a group that is not there refuses, with nothing
    /// written, and so does one deleted at the same moment.
    async fn join(&self, place: &Place, entity: &MembershipEntity) -> Result<()>;

    /// Delete the membership under `id`, answering whether there was one.
    async fn leave(&self, place: &Place, id: &str) -> Result<bool>;

    /// At most `count` members of the group `group` after the membership `after`, in id order.
    async fn members(
        &self,
        place: &Place,
        group: &str,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<MembershipEntity>>;

    /// At most `limit` memberships of the user `user`.
    async fn memberships(
        &self,
        place: &Place,
        user: &str,
        limit: u32,
    ) -> Result<Vec<MembershipEntity>>;
}
