//! Enrolment codes on TessariDB: the `enrolments` table, whose records expire on their own after 72 hours.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::EnrolmentEntity;
use super::repository::EnrolmentRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbEnrolmentRepository {
    database: Database,
}

impl TessaridbEnrolmentRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl EnrolmentRepository for TessaridbEnrolmentRepository {
    async fn issue(&self, place: &Place, digest: &str, entity: &EnrolmentEntity) -> Result<()> {
        // A user holds one live code: issuing another removes the earlier one in the same commit.
        self.database
            .run_at(
                place,
                "BEGIN; DELETE FROM enrolments WHERE user_id = $user LIMIT ALL; \
                 CREATE enrolments:$digest = { user_id: $user, created_at: $created_at, created_by: $by }; \
                 COMMIT;",
                vec![
                    ("user".to_owned(), Value::from(entity.user_id.as_str())),
                    ("digest".to_owned(), Value::from(digest)),
                    ("created_at".to_owned(), Value::from(entity.created_at)),
                    ("by".to_owned(), Value::from(entity.created_by.as_str())),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, digest: &str) -> Result<Option<EnrolmentEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM enrolments:$digest;",
                vec![("digest".to_owned(), Value::from(digest))],
            )
            .await?;
        answers::single(answers, "enrolment")
    }

    async fn redeem(&self, place: &Place, digest: &str) -> Result<Option<EnrolmentEntity>> {
        // One delete that answers what it removed: two redemptions racing see the record once.
        let answers = self
            .database
            .run_at(
                place,
                "DELETE enrolments:$digest RETURN BEFORE;",
                vec![("digest".to_owned(), Value::from(digest))],
            )
            .await?;
        answers::returned(answers, digest, "enrolment")
    }
}
