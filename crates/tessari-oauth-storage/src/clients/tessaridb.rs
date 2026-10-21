//! Client registrations on TessariDB: one `clients` record per client, under its id.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::ClientEntity;
use super::repository::ClientRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbClientRepository {
    database: Database,
}

impl TessaridbClientRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn texts(values: &[String]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::from(value.as_str()))
            .collect(),
    )
}

#[async_trait]
impl ClientRepository for TessaridbClientRepository {
    async fn create(&self, place: &Place, client: &ClientEntity) -> Result<()> {
        // `CREATE` refuses an id that exists, so a client is registered once and a second registration conflicts.
        self.database
            .run_at(
                place,
                "CREATE clients:$id = { client_id: $id, tenant: $tenant, redirect_uris: $redirect_uris, \
                 scope_ceiling: $scope_ceiling, auth_method: $auth_method, assertion_alg: $assertion_alg, \
                 grant_types: $grant_types, jwks: $jwks, registered_at: $registered_at };",
                vec![
                    ("id".to_owned(), Value::from(client.client_id.as_str())),
                    ("tenant".to_owned(), Value::from(client.tenant.as_str())),
                    ("redirect_uris".to_owned(), texts(&client.redirect_uris)),
                    ("scope_ceiling".to_owned(), texts(&client.scope_ceiling)),
                    ("auth_method".to_owned(), Value::from(client.auth_method.as_str())),
                    (
                        "assertion_alg".to_owned(),
                        client
                            .assertion_alg
                            .as_deref()
                            .map_or(Value::None, Value::from),
                    ),
                    ("grant_types".to_owned(), texts(&client.grant_types)),
                    ("jwks".to_owned(), texts(&client.jwks)),
                    ("registered_at".to_owned(), Value::from(client.registered_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, client_id: &str) -> Result<Option<ClientEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM clients:$id;",
                vec![("id".to_owned(), Value::from(client_id))],
            )
            .await?;
        answers::single(answers, "client")
    }
}
