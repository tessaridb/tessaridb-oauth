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
        let resources = Value::Array(
            code.resources
                .iter()
                .map(|resource| text(resource))
                .collect(),
        );
        self.database
            .run_at(
                place,
                "CREATE codes:$id = { tenant: $tenant, client_id: $client_id, user_id: $user_id, \
                 redirect_uri: $redirect_uri, challenge: $challenge, scopes: $scopes, resources: $resources, \
                 expires_at: $expires_at, auth_time: $auth_time, methods: $methods, sid: $sid, nonce: $nonce };",
                vec![
                    ("id".to_owned(), text(digest)),
                    ("tenant".to_owned(), text(&code.tenant)),
                    ("client_id".to_owned(), text(&code.client_id)),
                    ("user_id".to_owned(), text(&code.user_id)),
                    ("redirect_uri".to_owned(), text(&code.redirect_uri)),
                    ("challenge".to_owned(), text(&code.challenge)),
                    ("scopes".to_owned(), scopes),
                    ("resources".to_owned(), resources),
                    ("expires_at".to_owned(), Value::from(code.expires_at)),
                    ("auth_time".to_owned(), Value::from(code.auth_time)),
                    (
                        "methods".to_owned(),
                        Value::Array(code.methods.iter().map(|name| text(name)).collect()),
                    ),
                    ("sid".to_owned(), text(&code.sid)),
                    ("nonce".to_owned(), code.nonce.as_deref().map_or(Value::None, text)),
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
