//! Client registrations on TessariDB: one `clients` record per client, under its id, read by id or a page in
//! id order.

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
                 scope_ceiling: $scope_ceiling, resources: $resources, auth_method: $auth_method, \
                 assertion_alg: $assertion_alg, \
                 grant_types: $grant_types, jwks: $jwks, dpop_bound_access_tokens: $dpop_bound_access_tokens, \
                 registered_at: $registered_at, post_logout_redirect_uris: $post_logout_redirect_uris, \
                 backchannel_logout_uri: $backchannel_logout_uri };",
                vec![
                    ("id".to_owned(), Value::from(client.client_id.as_str())),
                    ("tenant".to_owned(), Value::from(client.tenant.as_str())),
                    ("redirect_uris".to_owned(), texts(&client.redirect_uris)),
                    ("scope_ceiling".to_owned(), texts(&client.scope_ceiling)),
                    ("resources".to_owned(), texts(&client.resources)),
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
                    (
                        "dpop_bound_access_tokens".to_owned(),
                        Value::from(client.dpop_bound_access_tokens),
                    ),
                    ("registered_at".to_owned(), Value::from(client.registered_at)),
                    (
                        "post_logout_redirect_uris".to_owned(),
                        client
                            .post_logout_redirect_uris
                            .as_deref()
                            .map_or(Value::None, texts),
                    ),
                    (
                        "backchannel_logout_uri".to_owned(),
                        client
                            .backchannel_logout_uri
                            .as_deref()
                            .map_or(Value::None, Value::from),
                    ),
                ],
            )
            .await?;
        Ok(())
    }

    async fn retarget(
        &self,
        place: &Place,
        client_id: &str,
        redirect_uris: &[String],
        resources: &[String],
    ) -> Result<()> {
        // `UPDATE` never invents a record, and `SET` leaves every field it does not name as registered.
        self.database
            .run_at(
                place,
                "UPDATE clients:$id SET redirect_uris = $redirect_uris, resources = $resources;",
                vec![
                    ("id".to_owned(), Value::from(client_id)),
                    ("redirect_uris".to_owned(), texts(redirect_uris)),
                    ("resources".to_owned(), texts(resources)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn page(
        &self,
        place: &Place,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<ClientEntity>> {
        let count = Value::from(i64::from(count));
        let answers = match after {
            Some(after) => {
                self.database
                    .run_at(
                        place,
                        "SELECT * FROM clients AFTER clients:$after LIMIT $count;",
                        vec![
                            ("after".to_owned(), Value::from(after)),
                            ("count".to_owned(), count),
                        ],
                    )
                    .await?
            }
            None => {
                self.database
                    .run_at(
                        place,
                        "SELECT * FROM clients LIMIT $count;",
                        vec![("count".to_owned(), count)],
                    )
                    .await?
            }
        };
        answers::records(answers, "client")
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
