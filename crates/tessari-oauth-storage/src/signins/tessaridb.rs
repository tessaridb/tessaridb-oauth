//! Sign-ins in progress on TessariDB, in a table whose records the store expires.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::SigninEntity;
use super::repository::SigninRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbSigninRepository {
    database: Database,
}

impl TessaridbSigninRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn progress(signin: &SigninEntity) -> Vec<(String, Value)> {
    vec![
        ("identified".to_owned(), Value::from(signin.identified)),
        (
            "user".to_owned(),
            signin.user_id.as_deref().map_or(Value::None, Value::from),
        ),
        ("second".to_owned(), Value::from(signin.second_factor)),
        (
            "account".to_owned(),
            signin.account.as_deref().map_or(Value::None, Value::from),
        ),
        (
            "methods".to_owned(),
            Value::Array(
                signin
                    .methods
                    .iter()
                    .map(|method| Value::from(method.as_str()))
                    .collect(),
            ),
        ),
    ]
}

#[async_trait]
impl SigninRepository for TessaridbSigninRepository {
    async fn create(&self, place: &Place, id: &str, signin: &SigninEntity) -> Result<()> {
        let mut values = progress(signin);
        values.extend([
            ("id".to_owned(), Value::from(id)),
            (
                "interaction".to_owned(),
                Value::from(signin.interaction.as_str()),
            ),
            ("revision".to_owned(), Value::from(signin.revision)),
            ("at".to_owned(), Value::from(signin.created_at)),
        ]);
        self.database
            .run_at(
                place,
                "CREATE signins:$id = { interaction: $interaction, identified: $identified, user_id: $user, \
                 second_factor: $second, account: $account, methods: $methods, revision: $revision, created_at: $at };",
                values,
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, id: &str) -> Result<Option<SigninEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM signins:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::single(answers, "sign-in")
    }

    async fn advance(
        &self,
        place: &Place,
        id: &str,
        revision: i64,
        signin: &SigninEntity,
    ) -> Result<()> {
        let mut values = progress(signin);
        values.extend([
            ("id".to_owned(), Value::from(id)),
            ("revision".to_owned(), Value::from(revision)),
            ("next".to_owned(), Value::from(signin.revision)),
        ]);
        self.database
            .run_at(
                place,
                "UPDATE signins:$id SET identified = $identified, user_id = $user, second_factor = $second, \
                 account = $account, methods = $methods, revision = $next WHERE revision = $revision;",
                values,
            )
            .await?;
        Ok(())
    }

    async fn take(&self, place: &Place, id: &str) -> Result<Option<SigninEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE signins:$id RETURN BEFORE;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::returned(answers, id, "sign-in")
    }
}
