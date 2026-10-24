//! The admin console's records on TessariDB: `admin_signins`, which the store expires after ten minutes,
//! `admin_sessions`, which it expires after eight hours, and `admin_actions`, which it expires after a day.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::repository::AdminRepository;
use super::{AdminActionEntity, AdminSessionEntity, PendingSigninEntity};
use crate::{Result, answers};

pub(crate) struct TessaridbAdminRepository {
    database: Database,
}

impl TessaridbAdminRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl AdminRepository for TessaridbAdminRepository {
    async fn begin(&self, place: &Place, id: &str, pending: &PendingSigninEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE admin_signins:$id = \
                 { state: $state, verifier: $verifier, nonce: $nonce, created_at: $at };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("state".to_owned(), Value::from(pending.state.as_str())),
                    (
                        "verifier".to_owned(),
                        Value::from(pending.verifier.as_str()),
                    ),
                    ("nonce".to_owned(), Value::from(pending.nonce.as_str())),
                    ("at".to_owned(), Value::from(pending.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn take(&self, place: &Place, id: &str) -> Result<Option<PendingSigninEntity>> {
        // One delete that answers what it removed: two callbacks racing see the sign-in once.
        let answers = self
            .database
            .run_at(
                place,
                "DELETE admin_signins:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "admin sign-in")
    }

    async fn open(&self, place: &Place, id: &str, session: &AdminSessionEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE admin_sessions:$id = \
                 { user_id: $user, sid: $sid, methods: $methods, auth_time: $at, seen_at: $seen };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("user".to_owned(), Value::from(session.user_id.as_str())),
                    ("sid".to_owned(), Value::from(session.sid.as_str())),
                    (
                        "methods".to_owned(),
                        Value::Array(
                            session
                                .methods
                                .iter()
                                .map(|name| Value::from(name.as_str()))
                                .collect(),
                        ),
                    ),
                    ("at".to_owned(), Value::from(session.auth_time)),
                    ("seen".to_owned(), Value::from(session.seen_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, id: &str) -> Result<Option<AdminSessionEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM admin_sessions:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::single(answers, "admin session")
    }

    async fn touch(&self, place: &Place, id: &str, seen_at: i64) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPDATE admin_sessions:$id SET seen_at = $seen WHERE seen_at < $seen;",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("seen".to_owned(), Value::from(seen_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn end(&self, place: &Place, id: &str) -> Result<Option<AdminSessionEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE admin_sessions:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "admin session")
    }

    async fn claim(&self, place: &Place, id: &str, action: &AdminActionEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE admin_actions:$id = \
                 { operator: $operator, action: $action, request: $request, created_at: $at };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("operator".to_owned(), Value::from(action.operator.as_str())),
                    ("action".to_owned(), Value::from(action.action.as_str())),
                    ("request".to_owned(), Value::from(action.request.as_str())),
                    ("at".to_owned(), Value::from(action.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn action(&self, place: &Place, id: &str) -> Result<Option<AdminActionEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM admin_actions:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::single(answers, "admin action")
    }

    async fn finish(&self, place: &Place, id: &str, status: i64, answer: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPDATE admin_actions:$id SET status = $status, answer = $answer;",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("status".to_owned(), Value::from(status)),
                    ("answer".to_owned(), Value::from(answer)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn release(&self, place: &Place, id: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "DELETE admin_actions:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        Ok(())
    }
}
