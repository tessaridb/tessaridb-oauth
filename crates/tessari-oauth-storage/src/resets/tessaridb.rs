//! Reset tokens on TessariDB: the `password_resets` table, whose records expire on their own after 30 minutes.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::ResetEntity;
use super::repository::ResetRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbResetRepository {
    database: Database,
}

impl TessaridbResetRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl ResetRepository for TessaridbResetRepository {
    async fn issue(&self, place: &Place, digest: &str, entity: &ResetEntity) -> Result<()> {
        // A user holds one live token: a newer request removes the earlier one in the same commit.
        self.database
            .run_at(
                place,
                "BEGIN; DELETE FROM password_resets WHERE user_id = $user LIMIT ALL; \
                 CREATE password_resets:$digest = { user_id: $user, created_at: $created_at }; COMMIT;",
                vec![
                    ("user".to_owned(), Value::from(entity.user_id.as_str())),
                    ("digest".to_owned(), Value::from(digest)),
                    ("created_at".to_owned(), Value::from(entity.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, digest: &str) -> Result<Option<ResetEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM password_resets:$digest;",
                vec![("digest".to_owned(), Value::from(digest))],
            )
            .await?;
        answers::single(answers, "password reset")
    }

    async fn redeem(&self, place: &Place, digest: &str) -> Result<Option<ResetEntity>> {
        // One delete that answers what it removed: two redemptions racing see the record once.
        let answers = self
            .database
            .run_at(
                place,
                "DELETE password_resets:$digest RETURN BEFORE;",
                vec![("digest".to_owned(), Value::from(digest))],
            )
            .await?;
        answers::returned(answers, digest, "password reset")
    }

    async fn cancel(&self, place: &Place, user_id: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "DELETE FROM password_resets WHERE user_id = $user LIMIT ALL;",
                vec![("user".to_owned(), Value::from(user_id))],
            )
            .await?;
        Ok(())
    }
}
