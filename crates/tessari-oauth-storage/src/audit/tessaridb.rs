//! The audit trail on TessariDB: the `audit` topic, which the store refuses to rewrite or delete from.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::AuditEntity;
use super::entity::AuditMessageEntity;
use super::repository::AuditRepository;
use crate::{Error, Result, answers};

pub(crate) struct TessaridbAuditRepository {
    database: Database,
}

impl TessaridbAuditRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn text(value: Option<&String>) -> Value {
    value.map_or(Value::None, |value| Value::from(value.as_str()))
}

fn count(value: u64) -> Result<Value> {
    i64::try_from(value)
        .map(Value::from)
        .map_err(|_| Error::Invalid {
            record: "audit message",
            reason: "a count beyond i64",
        })
}

#[async_trait]
impl AuditRepository for TessaridbAuditRepository {
    async fn append(&self, place: &Place, id: &str, message: &AuditEntity) -> Result<()> {
        let scopes = message.scopes.as_ref().map_or(Value::None, |scopes| {
            Value::Array(
                scopes
                    .iter()
                    .map(|scope| Value::from(scope.as_str()))
                    .collect(),
            )
        });
        self.database
            .run_at(
                place,
                "CREATE audit:$id = { kind: $kind, client_id: $client_id, user_id: $user_id, subject: $subject, \
                 scopes: $scopes, audience: $audience, jti: $jti, auth_method: $auth_method, jkt: $jkt, \
                 reason: $reason, families: $families, actor: $actor, role_name: $role, action: $action, \
                 at: $at };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("kind".to_owned(), Value::from(message.kind.as_str())),
                    ("client_id".to_owned(), text(message.client_id.as_ref())),
                    ("user_id".to_owned(), text(message.user_id.as_ref())),
                    ("subject".to_owned(), text(message.subject.as_ref())),
                    ("scopes".to_owned(), scopes),
                    ("audience".to_owned(), text(message.audience.as_ref())),
                    ("jti".to_owned(), text(message.jti.as_ref())),
                    ("auth_method".to_owned(), text(message.auth_method.as_ref())),
                    ("jkt".to_owned(), text(message.jkt.as_ref())),
                    ("reason".to_owned(), text(message.reason.as_ref())),
                    (
                        "families".to_owned(),
                        message.families.map_or(Value::None, Value::from),
                    ),
                    ("actor".to_owned(), text(message.actor.as_ref())),
                    ("role".to_owned(), text(message.role_name.as_ref())),
                    ("action".to_owned(), text(message.action.as_ref())),
                    ("at".to_owned(), Value::from(message.at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn read_after(
        &self,
        place: &Place,
        after: u64,
        limit: u64,
    ) -> Result<Vec<AuditMessageEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "READ FROM audit AFTER $after LIMIT $limit;",
                vec![
                    ("after".to_owned(), count(after)?),
                    ("limit".to_owned(), count(limit)?),
                ],
            )
            .await?;
        answers::records(answers, "audit message")
    }
}
