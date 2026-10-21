//! Codes on TessariDB.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::CodeEntity;
use super::repository::CodeRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbCodeRepository {
    database: Database,
}

impl TessaridbCodeRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn text(value: &str) -> Value {
    Value::from(value)
}

#[async_trait]
impl CodeRepository for TessaridbCodeRepository {
    async fn create(&self, place: &Place, digest: &str, code: &CodeEntity) -> Result<()> {
        let scopes = Value::Array(code.scopes.iter().map(|scope| text(scope)).collect());
        self.database
            .run_at(
                place,
                "CREATE codes:$id = { tenant: $tenant, client_id: $client_id, user_id: $user_id, \
                 redirect_uri: $redirect_uri, challenge: $challenge, scopes: $scopes, expires_at: $expires_at };",
                vec![
                    ("id".to_owned(), text(digest)),
                    ("tenant".to_owned(), text(&code.tenant)),
                    ("client_id".to_owned(), text(&code.client_id)),
                    ("user_id".to_owned(), text(&code.user_id)),
                    ("redirect_uri".to_owned(), text(&code.redirect_uri)),
                    ("challenge".to_owned(), text(&code.challenge)),
                    ("scopes".to_owned(), scopes),
                    ("expires_at".to_owned(), Value::from(code.expires_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, digest: &str) -> Result<Option<CodeEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM codes:$id;",
                vec![("id".to_owned(), text(digest))],
            )
            .await?;
        answers::single(answers, "code")
    }

    async fn mark_redeemed(
        &self,
        place: &Place,
        digest: &str,
        at: i64,
    ) -> Result<Option<CodeEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "UPDATE codes:$id SET redeemed_at = $at WHERE redeemed_at = NONE RETURN BEFORE;",
                vec![
                    ("id".to_owned(), text(digest)),
                    ("at".to_owned(), Value::from(at)),
                ],
            )
            .await?;
        answers::returned(answers, digest, "code")
    }
}
