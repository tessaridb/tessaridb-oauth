//! Refresh families on TessariDB.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::repository::RefreshRepository;
use super::{FamilyEntity, FamilyIdEntity, Holder, TokenEntity};
use crate::{Error, Result, answers};

pub(crate) struct TessaridbRefreshRepository {
    database: Database,
}

impl TessaridbRefreshRepository {
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

/// The values a new token binds, under the `token_` prefix so one script can also bind its family's.
fn token_values(id: &str, token: &TokenEntity) -> Vec<(String, Value)> {
    vec![
        ("token_id".to_owned(), text(id)),
        ("token_family_id".to_owned(), text(&token.family_id)),
        ("token_tenant".to_owned(), text(&token.tenant)),
        ("token_client_id".to_owned(), text(&token.client_id)),
        ("token_user_id".to_owned(), text(&token.user_id)),
        ("token_scopes".to_owned(), texts(&token.scopes)),
        ("token_resources".to_owned(), texts(&token.resources)),
        (
            "token_idle_expires_at".to_owned(),
            Value::from(token.idle_expires_at),
        ),
        (
            "token_jkt".to_owned(),
            token.jkt.as_deref().map_or(Value::None, text),
        ),
    ]
}

/// The text a text id spells: the node writes it in single quotes, like any other text. A family id is a digest, so a
/// spelling with anything to unescape is not one this crate wrote and is refused rather than guessed at.
fn text_id(spelled: &str) -> Result<String> {
    spelled
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
        .filter(|inner| !inner.contains(['\'', '\\']))
        .map(str::to_owned)
        .ok_or_else(|| Error::Unreadable {
            record: "refresh family",
            reason: "an id that is not plain quoted text".to_owned(),
        })
}

const CREATE_TOKEN: &str = "CREATE refresh_tokens:$token_id = { family_id: $token_family_id, \
     tenant: $token_tenant, client_id: $token_client_id, user_id: $token_user_id, scopes: $token_scopes, \
     resources: $token_resources, idle_expires_at: $token_idle_expires_at, jkt: $token_jkt };";

#[async_trait]
impl RefreshRepository for TessaridbRefreshRepository {
    async fn start(
        &self,
        place: &Place,
        family_id: &str,
        family: &FamilyEntity,
        token_id: &str,
        token: &TokenEntity,
    ) -> Result<()> {
        let mut values = token_values(token_id, token);
        values.extend([
            ("family_id".to_owned(), text(family_id)),
            ("tenant".to_owned(), text(&family.tenant)),
            ("client_id".to_owned(), text(&family.client_id)),
            ("user_id".to_owned(), text(&family.user_id)),
            ("created_at".to_owned(), Value::from(family.created_at)),
            ("expires_at".to_owned(), Value::from(family.expires_at)),
        ]);
        let script = format!(
            "BEGIN; CREATE refresh_families:$family_id = {{ tenant: $tenant, client_id: $client_id, \
             user_id: $user_id, created_at: $created_at, expires_at: $expires_at }}; {CREATE_TOKEN} COMMIT;"
        );
        self.database.run_at(place, &script, values).await?;
        Ok(())
    }

    async fn create_family(&self, place: &Place, id: &str, family: &FamilyEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE refresh_families:$id = { tenant: $tenant, client_id: $client_id, user_id: $user_id, \
                 created_at: $created_at, expires_at: $expires_at, revoked_at: $revoked_at, \
                 revoked_reason: $revoked_reason };",
                vec![
                    ("id".to_owned(), text(id)),
                    ("tenant".to_owned(), text(&family.tenant)),
                    ("client_id".to_owned(), text(&family.client_id)),
                    ("user_id".to_owned(), text(&family.user_id)),
                    ("created_at".to_owned(), Value::from(family.created_at)),
                    ("expires_at".to_owned(), Value::from(family.expires_at)),
                    ("revoked_at".to_owned(), family.revoked_at.map_or(Value::None, Value::from)),
                    (
                        "revoked_reason".to_owned(),
                        family.revoked_reason.as_deref().map_or(Value::None, text),
                    ),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_token(&self, place: &Place, id: &str) -> Result<Option<TokenEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM refresh_tokens:$id;",
                vec![("id".to_owned(), text(id))],
            )
            .await?;
        answers::single(answers, "refresh token")
    }

    async fn find_family(&self, place: &Place, id: &str) -> Result<Option<FamilyEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM refresh_families:$id;",
                vec![("id".to_owned(), text(id))],
            )
            .await?;
        answers::single(answers, "refresh family")
    }

    async fn rotate(
        &self,
        place: &Place,
        spent: &str,
        at: i64,
        next_id: &str,
        next: &TokenEntity,
    ) -> Result<()> {
        let mut values = token_values(next_id, next);
        values.extend([
            ("spent".to_owned(), text(spent)),
            ("at".to_owned(), Value::from(at)),
        ]);
        let script = format!(
            "BEGIN; UPDATE refresh_tokens:$spent SET rotated_at = $at WHERE rotated_at = NONE; {CREATE_TOKEN} COMMIT;"
        );
        self.database.run_at(place, &script, values).await?;
        Ok(())
    }

    async fn standing(&self, place: &Place, holder: &Holder<'_>) -> Result<Vec<String>> {
        let (statement, values) = match holder {
            Holder::User(user) => (
                "SELECT id FROM refresh_families WHERE user_id = $user_id AND revoked_at = NONE \
                 USING INDEX by_user;",
                vec![("user_id".to_owned(), text(user.as_str()))],
            ),
            Holder::Client(client) => (
                "SELECT id FROM refresh_families WHERE client_id = $client_id AND revoked_at = NONE \
                 USING INDEX by_client;",
                vec![("client_id".to_owned(), text(client.as_str()))],
            ),
            Holder::Grant { user, client } => (
                "SELECT id FROM refresh_families WHERE user_id = $user_id AND client_id = $client_id \
                 AND revoked_at = NONE USING INDEX by_user;",
                vec![
                    ("user_id".to_owned(), text(user.as_str())),
                    ("client_id".to_owned(), text(client.as_str())),
                ],
            ),
        };
        let answers = self.database.run_at(place, statement, values).await?;
        answers::records::<FamilyIdEntity>(answers, "refresh family")?
            .iter()
            .map(|family| text_id(&family.spelled))
            .collect()
    }

    async fn revoke_family(&self, place: &Place, id: &str, at: i64, reason: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPDATE refresh_families:$id SET revoked_at = $at, revoked_reason = $reason \
                 WHERE revoked_at = NONE;",
                vec![
                    ("id".to_owned(), text(id)),
                    ("at".to_owned(), Value::from(at)),
                    ("reason".to_owned(), text(reason)),
                ],
            )
            .await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tessaridb_tests.rs"]
mod tests;
