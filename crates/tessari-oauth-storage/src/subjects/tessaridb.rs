//! Sealed secrets on TessariDB: one `secrets` record per purpose, and one `pairwise_subjects` record per derived
//! subject.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::repository::SecretRepository;
use super::{SecretEntity, SubjectEntity};
use crate::{Result, answers};

pub(crate) struct TessaridbSecretRepository {
    database: Database,
}

impl TessaridbSecretRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl SecretRepository for TessaridbSecretRepository {
    async fn create(&self, place: &Place, purpose: &str, secret: &SecretEntity) -> Result<()> {
        // `CREATE` refuses an id that exists, so a secret is made once and a second making conflicts.
        self.database
            .run_at(
                place,
                "CREATE secrets:$id = { sealed: $sealed, created_at: $created_at };",
                vec![
                    ("id".to_owned(), Value::from(purpose)),
                    ("sealed".to_owned(), Value::from(secret.sealed.as_str())),
                    ("created_at".to_owned(), Value::from(secret.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, purpose: &str) -> Result<Option<SecretEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM secrets:$id;",
                vec![("id".to_owned(), Value::from(purpose))],
            )
            .await?;
        answers::single(answers, "secret")
    }

    async fn create_subject(
        &self,
        place: &Place,
        subject: &str,
        entity: &SubjectEntity,
    ) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE pairwise_subjects:$id = { client_id: $client, user_id: $user };",
                vec![
                    ("id".to_owned(), Value::from(subject)),
                    ("client".to_owned(), Value::from(entity.client_id.as_str())),
                    ("user".to_owned(), Value::from(entity.user_id.as_str())),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_subject(&self, place: &Place, subject: &str) -> Result<Option<SubjectEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM pairwise_subjects:$id;",
                vec![("id".to_owned(), Value::from(subject))],
            )
            .await?;
        answers::single(answers, "pairwise subject")
    }
}
