//! Sessions on TessariDB, in a table whose records the store expires a week after they are made.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::SessionEntity;
use super::repository::SessionRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbSessionRepository {
    database: Database,
}

impl TessaridbSessionRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl SessionRepository for TessaridbSessionRepository {
    async fn create(&self, place: &Place, id: &str, session: &SessionEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE sessions:$id = { user_id: $user, methods: $methods, auth_time: $at, seen_at: $seen };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("user".to_owned(), Value::from(session.user_id.as_str())),
                    (
                        "methods".to_owned(),
                        Value::Array(session.methods.iter().map(|name| Value::from(name.as_str())).collect()),
                    ),
                    ("at".to_owned(), Value::from(session.auth_time)),
                    ("seen".to_owned(), Value::from(session.seen_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, id: &str) -> Result<Option<SessionEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM sessions:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::single(answers, "session")
    }

    async fn touch(&self, place: &Place, id: &str, seen_at: i64) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPDATE sessions:$id SET seen_at = $seen WHERE seen_at < $seen;",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("seen".to_owned(), Value::from(seen_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn take(&self, place: &Place, id: &str) -> Result<Option<SessionEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE sessions:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "session")
    }
}
