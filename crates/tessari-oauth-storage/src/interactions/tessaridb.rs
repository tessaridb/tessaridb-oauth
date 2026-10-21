//! Pending authorizations on TessariDB, in a table whose records the store expires.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::InteractionEntity;
use super::repository::InteractionRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbInteractionRepository {
    database: Database,
}

impl TessaridbInteractionRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn text(value: &str) -> Value {
    Value::from(value)
}

fn texts(values: &[String]) -> Value {
    Value::Array(values.iter().map(|value| text(value)).collect())
}

#[async_trait]
impl InteractionRepository for TessaridbInteractionRepository {
    async fn create(&self, place: &Place, id: &str, interaction: &InteractionEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE interactions:$id = { tenant: $tenant, client_id: $client_id, redirect_uri: $redirect_uri, \
                 scopes: $scopes, challenge: $challenge, state: $state, resources: $resources, nonce: $nonce, \
                 created_at: $created_at };",
                vec![
                    ("id".to_owned(), text(id)),
                    ("tenant".to_owned(), text(&interaction.tenant)),
                    ("client_id".to_owned(), text(&interaction.client_id)),
                    ("redirect_uri".to_owned(), text(&interaction.redirect_uri)),
                    ("scopes".to_owned(), texts(&interaction.scopes)),
                    ("challenge".to_owned(), text(&interaction.challenge)),
                    (
                        "state".to_owned(),
                        interaction.state.as_deref().map_or(Value::None, text),
                    ),
                    ("resources".to_owned(), texts(&interaction.resources)),
                    (
                        "nonce".to_owned(),
                        interaction.nonce.as_deref().map_or(Value::None, text),
                    ),
                    ("created_at".to_owned(), Value::from(interaction.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, id: &str) -> Result<Option<InteractionEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM interactions:$id;",
                vec![("id".to_owned(), text(id))],
            )
            .await?;
        answers::single(answers, "interaction")
    }
}
