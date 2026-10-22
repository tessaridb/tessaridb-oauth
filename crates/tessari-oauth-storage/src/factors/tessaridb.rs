//! Second factors on TessariDB: `totp_factors:<user>` and `recovery_codes:<user>.<digest>`.
//!
//! A recovery code's id names its owner as well as its digest, so a delete by that id can only ever reach the
//! caller's own code: another user's digest under this user's name addresses nothing.

use std::fmt::Write as _;

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::TotpEntity;
use super::entity::CodeEntity;
use super::repository::FactorRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbFactorRepository {
    database: Database,
}

impl TessaridbFactorRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

/// The id of `user_id`'s recovery code under `digest`; the digest has a fixed length, so the join is unambiguous.
fn code_id(user_id: &str, digest: &str) -> String {
    format!("{user_id}.{digest}")
}

#[async_trait]
impl FactorRepository for TessaridbFactorRepository {
    async fn create_totp(&self, place: &Place, factor: &TotpEntity) -> Result<()> {
        // `CREATE` refuses an id that exists, so a user has one factor and a second enrolment conflicts.
        self.database
            .run_at(
                place,
                "CREATE totp_factors:$id = { user_id: $id, sealed: $sealed, last_step: $last_step, \
                 created_at: $created_at };",
                vec![
                    ("id".to_owned(), Value::from(factor.user_id.as_str())),
                    ("sealed".to_owned(), Value::from(factor.sealed.as_str())),
                    ("last_step".to_owned(), Value::from(factor.last_step)),
                    ("created_at".to_owned(), Value::from(factor.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_totp(&self, place: &Place, user_id: &str) -> Result<Option<TotpEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM totp_factors:$id;",
                vec![("id".to_owned(), Value::from(user_id))],
            )
            .await?;
        answers::single(answers, "totp factor")
    }

    async fn advance_step(&self, place: &Place, user_id: &str, step: i64) -> Result<()> {
        // A compare-and-set: the condition false refuses, so of two requests holding one code only one moves it.
        self.database
            .run_at(
                place,
                "UPDATE totp_factors:$id SET last_step = $step WHERE last_step < $step;",
                vec![
                    ("id".to_owned(), Value::from(user_id)),
                    ("step".to_owned(), Value::from(step)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn replace_codes(
        &self,
        place: &Place,
        user_id: &str,
        digests: &[String],
        created_at: i64,
    ) -> Result<()> {
        // Every code of the user goes, deliberately all of them, and the new set lands in the same commit.
        let mut script =
            String::from("BEGIN; DELETE FROM recovery_codes WHERE user_id = $user LIMIT ALL; ");
        let mut values = vec![
            ("user".to_owned(), Value::from(user_id)),
            ("at".to_owned(), Value::from(created_at)),
        ];
        for (position, digest) in digests.iter().enumerate() {
            // Only the parameter's name is generated here; the digest itself is bound.
            let _ = write!(
                script,
                "CREATE recovery_codes:$code{position} = {{ user_id: $user, created_at: $at }}; "
            );
            values.push((
                format!("code{position}"),
                Value::from(code_id(user_id, digest)),
            ));
        }
        script.push_str("COMMIT;");
        self.database.run_at(place, &script, values).await?;
        Ok(())
    }

    async fn delete_code(&self, place: &Place, user_id: &str, digest: &str) -> Result<bool> {
        let id = code_id(user_id, digest);
        let answers = self
            .database
            .run_at(
                place,
                "DELETE recovery_codes:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id.as_str()))],
            )
            .await?;
        Ok(answers::returned::<CodeEntity>(answers, &id, "recovery code")?.is_some())
    }
}
