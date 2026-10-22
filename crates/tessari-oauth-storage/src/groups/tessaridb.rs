//! Groups on TessariDB: the `groups` and `group_members` tables of each company's database.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::repository::GroupRepository;
use super::{GroupEntity, MembershipEntity};
use crate::{Result, answers};

pub(crate) struct TessaridbGroupRepository {
    database: Database,
}

impl TessaridbGroupRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn texts(values: &[String]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::from(value.as_str()))
            .collect(),
    )
}

#[async_trait]
impl GroupRepository for TessaridbGroupRepository {
    async fn create(&self, place: &Place, entity: &GroupEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE groups:$id = { group_id: $id, tenant: $tenant, description: $description, roles: $roles, \
                 created_at: $at };",
                vec![
                    ("id".to_owned(), Value::from(entity.group_id.as_str())),
                    ("tenant".to_owned(), Value::from(entity.tenant.as_str())),
                    (
                        "description".to_owned(),
                        Value::from(entity.description.as_str()),
                    ),
                    ("roles".to_owned(), texts(&entity.roles)),
                    ("at".to_owned(), Value::from(entity.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, id: &str) -> Result<Option<GroupEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM groups:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::single(answers, "group")
    }

    async fn find_many(&self, place: &Place, ids: &[String]) -> Result<Vec<GroupEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM groups WHERE group_id IN $ids LIMIT $limit;",
                vec![
                    ("ids".to_owned(), texts(ids)),
                    (
                        "limit".to_owned(),
                        Value::from(i64::try_from(ids.len()).unwrap_or(i64::MAX)),
                    ),
                ],
            )
            .await?;
        answers::records(answers, "group")
    }

    async fn page(
        &self,
        place: &Place,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<GroupEntity>> {
        let mut parameters = vec![("count".to_owned(), Value::from(i64::from(count)))];
        let statement = match after {
            Some(after) => {
                parameters.push(("after".to_owned(), Value::from(after)));
                "SELECT * FROM groups AFTER groups:$after LIMIT $count;"
            }
            None => "SELECT * FROM groups LIMIT $count;",
        };
        let answers = self.database.run_at(place, statement, parameters).await?;
        answers::records(answers, "group")
    }

    async fn set_roles(&self, place: &Place, id: &str, roles: &[String]) -> Result<()> {
        // The condition is a compare-and-set: a group that is not there refuses rather than being made by the write.
        self.database
            .run_at(
                place,
                "UPDATE groups:$id SET roles = $roles WHERE group_id = $id;",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("roles".to_owned(), texts(roles)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn delete(&self, place: &Place, id: &str) -> Result<()> {
        // One transaction, so no membership outlives its group to be inherited by a group made later under the id.
        self.database
            .run_at(
                place,
                "BEGIN; \
                 DELETE FROM group_members WHERE group_id = $id LIMIT ALL; \
                 DELETE groups:$id; \
                 COMMIT;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        Ok(())
    }

    async fn join(&self, place: &Place, entity: &MembershipEntity) -> Result<()> {
        // Touching the group in the same transaction makes a delete of it at the same moment a write-write conflict,
        // and its condition refuses a group that is not there, so a membership never stands without its group.
        self.database
            .run_at(
                place,
                "BEGIN; \
                 UPDATE groups:$group SET group_id = $group WHERE group_id = $group; \
                 UPSERT group_members:$id = { group_id: $group, user_id: $user, added_at: $at, added_by: $by }; \
                 COMMIT;",
                vec![
                    (
                        "id".to_owned(),
                        Value::from(format!("{}.{}", entity.group_id, entity.user_id)),
                    ),
                    ("group".to_owned(), Value::from(entity.group_id.as_str())),
                    ("user".to_owned(), Value::from(entity.user_id.as_str())),
                    ("at".to_owned(), Value::from(entity.added_at)),
                    ("by".to_owned(), Value::from(entity.added_by.as_str())),
                ],
            )
            .await?;
        Ok(())
    }

    async fn leave(&self, place: &Place, id: &str) -> Result<bool> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE group_members:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        Ok(answers::returned::<MembershipEntity>(answers, id, "group membership")?.is_some())
    }

    async fn members(
        &self,
        place: &Place,
        group: &str,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<MembershipEntity>> {
        let mut parameters = vec![
            ("group".to_owned(), Value::from(group)),
            ("count".to_owned(), Value::from(i64::from(count))),
        ];
        let statement = match after {
            Some(after) => {
                parameters.push(("after".to_owned(), Value::from(after)));
                "SELECT * FROM group_members WHERE group_id = $group AFTER group_members:$after LIMIT $count \
                 USING INDEX by_group;"
            }
            None => {
                "SELECT * FROM group_members WHERE group_id = $group LIMIT $count USING INDEX by_group;"
            }
        };
        let answers = self.database.run_at(place, statement, parameters).await?;
        answers::records(answers, "group membership")
    }

    async fn memberships(
        &self,
        place: &Place,
        user: &str,
        limit: u32,
    ) -> Result<Vec<MembershipEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM group_members WHERE user_id = $user LIMIT $limit USING INDEX by_user;",
                vec![
                    ("user".to_owned(), Value::from(user)),
                    ("limit".to_owned(), Value::from(i64::from(limit))),
                ],
            )
            .await?;
        answers::records(answers, "group membership")
    }
}
