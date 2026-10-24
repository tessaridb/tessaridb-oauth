//! Queued mail on TessariDB: the `mail_outbox` queue, whose hold lapses on its own.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::MailEntity;
use super::entity::ClaimedEntity;
use super::repository::OutboxRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbOutboxRepository {
    database: Database,
}

impl TessaridbOutboxRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl OutboxRepository for TessaridbOutboxRepository {
    async fn enqueue(&self, place: &Place, id: &str, sealed: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE mail_outbox:$id = { sealed: $sealed, due: time::now() };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("sealed".to_owned(), Value::from(sealed)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn claim(&self, place: &Place, count: u32) -> Result<Vec<ClaimedEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "CLAIM $count FROM mail_outbox;",
                vec![("count".to_owned(), Value::from(i64::from(count)))],
            )
            .await?;
        answers::records(answers, "queued mail")
    }

    async fn retry(&self, place: &Place, id: &str, after_secs: i64) -> Result<()> {
        self.database
            .run_at(
                place,
                "RELEASE mail_outbox:$id NOT BEFORE duration::from_secs($after);",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("after".to_owned(), Value::from(after_secs)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn finish(&self, place: &Place, id: &str) -> Result<Option<MailEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE mail_outbox:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "queued mail")
    }
}
