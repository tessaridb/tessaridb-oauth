//! Owed logouts on TessariDB: the `logout_deliveries` queue, whose hold lapses on its own.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::DeliveryEntity;
use super::entity::ClaimedEntity;
use super::repository::LogoutRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbLogoutRepository {
    database: Database,
}

impl TessaridbLogoutRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl LogoutRepository for TessaridbLogoutRepository {
    async fn claim(&self, place: &Place, count: u32) -> Result<Vec<ClaimedEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "CLAIM $count FROM logout_deliveries;",
                vec![("count".to_owned(), Value::from(i64::from(count)))],
            )
            .await?;
        answers::records(answers, "logout delivery")
    }

    async fn finish(&self, place: &Place, id: &str) -> Result<Option<DeliveryEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE logout_deliveries:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "logout delivery")
    }
}
