//! Passkeys on TessariDB: `passkeys:<credential id>` and `passkey_challenges:<challenge>`, both ids in base64url.
//!
//! A credential's record id IS its credential id, so `CREATE` refusing an existing id is what gives a credential one
//! owner. A challenge is spent by one delete of its record, so of two answers carrying it only one finds it; the table
//! expires its records, and the service also checks the age by its own clock.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::entity::ListedPasskeyEntity;
use super::repository::PasskeyRepository;
use super::{ChallengeEntity, PasskeyEntity};
use crate::{Result, answers};

pub(crate) struct TessaridbPasskeyRepository {
    database: Database,
}

impl TessaridbPasskeyRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl PasskeyRepository for TessaridbPasskeyRepository {
    async fn create_passkey(&self, place: &Place, id: &str, passkey: &PasskeyEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE passkeys:$id = { user_id: $user, public_key: $key, sign_count: $count, \
                 backup_eligible: $eligible, created_at: $at };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("user".to_owned(), Value::from(passkey.user_id.as_str())),
                    ("key".to_owned(), Value::from(passkey.public_key.as_str())),
                    ("count".to_owned(), Value::from(passkey.sign_count)),
                    ("eligible".to_owned(), Value::from(passkey.backup_eligible)),
                    ("at".to_owned(), Value::from(passkey.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_passkey(&self, place: &Place, id: &str) -> Result<Option<PasskeyEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM passkeys:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::single(answers, "passkey")
    }

    async fn advance_count(&self, place: &Place, id: &str, count: i64) -> Result<()> {
        // A compare-and-set: the condition false refuses, so a counter never moves back and one report moves it once.
        self.database
            .run_at(
                place,
                "UPDATE passkeys:$id SET sign_count = $count WHERE sign_count < $count;",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("count".to_owned(), Value::from(count)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn create_challenge(
        &self,
        place: &Place,
        id: &str,
        challenge: &ChallengeEntity,
    ) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE passkey_challenges:$id = { ceremony: $ceremony, user_id: $user, created_at: $at };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("ceremony".to_owned(), Value::from(challenge.ceremony.as_str())),
                    (
                        "user".to_owned(),
                        challenge.user_id.as_deref().map_or(Value::None, Value::from),
                    ),
                    ("at".to_owned(), Value::from(challenge.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn take_challenge(&self, place: &Place, id: &str) -> Result<Option<ChallengeEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE passkey_challenges:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "passkey challenge")
    }

    async fn list_for_user(
        &self,
        place: &Place,
        user_id: &str,
    ) -> Result<Vec<ListedPasskeyEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM passkeys WHERE user_id = $user USING INDEX by_user;",
                vec![("user".to_owned(), Value::from(user_id))],
            )
            .await?;
        answers::records(answers, "passkey")
    }

    async fn take_passkey(&self, place: &Place, id: &str) -> Result<Option<PasskeyEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE passkeys:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "passkey")
    }
}
