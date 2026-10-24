//! Operator grants on TessariDB: the `operator_grants` table of each company's database.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::OperatorGrantEntity;
use super::repository::OperatorRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbOperatorRepository {
    database: Database,
}

impl TessaridbOperatorRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl OperatorRepository for TessaridbOperatorRepository {
    async fn put(&self, place: &Place, id: &str, entity: &OperatorGrantEntity) -> Result<()> {
        // The whole grant: a re-grant replaces the reason and the expiry rather than keeping an older one.
        self.database
            .run_at(
                place,
                "UPSERT operator_grants:$id = { user_id: $user, role_name: $role, granted_by: $by, \
                 granted_at: $at, reason: $reason, expires_at: $expires };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("user".to_owned(), Value::from(entity.user_id.as_str())),
                    ("role".to_owned(), Value::from(entity.role_name.as_str())),
                    ("by".to_owned(), Value::from(entity.granted_by.as_str())),
                    ("at".to_owned(), Value::from(entity.granted_at)),
                    ("reason".to_owned(), Value::from(entity.reason.as_str())),
                    (
                        "expires".to_owned(),
                        entity.expires_at.map_or(Value::None, Value::from),
                    ),
                ],
            )
            .await?;
        Ok(())
    }

    async fn delete(&self, place: &Place, id: &str) -> Result<Option<OperatorGrantEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE operator_grants:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "operator grant")
    }

    async fn current(
        &self,
        place: &Place,
        user: &str,
        now: i64,
        limit: i64,
    ) -> Result<Vec<OperatorGrantEntity>> {
        // Expiry is applied here, in the read, so an expired grant never reaches a caller that forgot to look.
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM operator_grants WHERE user_id = $user \
                 AND (expires_at = NONE OR expires_at > $now) LIMIT $limit;",
                vec![
                    ("user".to_owned(), Value::from(user)),
                    ("now".to_owned(), Value::from(now)),
                    ("limit".to_owned(), Value::from(limit)),
                ],
            )
            .await?;
        answers::records(answers, "operator grant")
    }

    async fn page(
        &self,
        place: &Place,
        roles: &[&str],
        after: Option<&str>,
        count: u32,
        now: i64,
    ) -> Result<Vec<OperatorGrantEntity>> {
        // The roles and the expiry are applied in the read, so a grant the caller may not see never leaves the store.
        let mut parameters = vec![
            (
                "roles".to_owned(),
                Value::Array(roles.iter().map(|role| Value::from(*role)).collect()),
            ),
            ("now".to_owned(), Value::from(now)),
            ("count".to_owned(), Value::from(i64::from(count))),
        ];
        let statement = match after {
            Some(after) => {
                parameters.push(("after".to_owned(), Value::from(after)));
                "SELECT * FROM operator_grants WHERE role_name IN $roles \
                 AND (expires_at = NONE OR expires_at > $now) AFTER operator_grants:$after LIMIT $count;"
            }
            None => {
                "SELECT * FROM operator_grants WHERE role_name IN $roles \
                 AND (expires_at = NONE OR expires_at > $now) LIMIT $count;"
            }
        };
        let answers = self.database.run_at(place, statement, parameters).await?;
        answers::records(answers, "operator grant")
    }
}
