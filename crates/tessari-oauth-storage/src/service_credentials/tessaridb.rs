//! Registered services on TessariDB: the `services` table of each company's database.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::ServiceEntity;
use super::repository::ServiceRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbServiceRepository {
    database: Database,
}

impl TessaridbServiceRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl ServiceRepository for TessaridbServiceRepository {
    async fn create(&self, place: &Place, entity: &ServiceEntity) -> Result<()> {
        // `CREATE` refuses an id that exists, so a service is registered once and a second registration conflicts.
        self.database
            .run_at(
                place,
                "CREATE services:$id = { service_id: $id, public_jwk: $jwk, roles: $roles, \
                 registered_by: $by, registered_at: $at, reason: $reason };",
                vec![
                    ("id".to_owned(), Value::from(entity.service_id.as_str())),
                    ("jwk".to_owned(), Value::from(entity.public_jwk.as_str())),
                    (
                        "roles".to_owned(),
                        Value::Array(
                            entity
                                .roles
                                .iter()
                                .map(|role| Value::from(role.as_str()))
                                .collect(),
                        ),
                    ),
                    ("by".to_owned(), Value::from(entity.registered_by.as_str())),
                    ("at".to_owned(), Value::from(entity.registered_at)),
                    ("reason".to_owned(), Value::from(entity.reason.as_str())),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, id: &str) -> Result<Option<ServiceEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM services:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::single(answers, "service")
    }

    async fn list(&self, place: &Place, count: i64) -> Result<Vec<ServiceEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM services LIMIT $count;",
                vec![("count".to_owned(), Value::from(count))],
            )
            .await?;
        answers::records(answers, "service")
    }

    async fn delete(&self, place: &Place, id: &str) -> Result<Option<ServiceEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE services:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "service")
    }
}
