//! Consents on TessariDB.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::ConsentEntity;
use super::repository::ConsentRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbConsentRepository {
    database: Database,
}

impl TessaridbConsentRepository {
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

/// The values every write of a grant binds.
fn grant_values(id: &str, consent: &ConsentEntity) -> Vec<(String, Value)> {
    vec![
        ("id".to_owned(), text(id)),
        ("tenant".to_owned(), text(&consent.tenant)),
        ("user_id".to_owned(), text(&consent.user_id)),
        ("client_id".to_owned(), text(&consent.client_id)),
        ("scopes".to_owned(), texts(&consent.scopes)),
        ("resources".to_owned(), texts(&consent.resources)),
        (
            "policy_version".to_owned(),
            Value::from(consent.policy_version),
        ),
        ("shown_version".to_owned(), text(&consent.shown_version)),
        ("granted_at".to_owned(), Value::from(consent.granted_at)),
        ("revision".to_owned(), Value::from(consent.revision)),
    ]
}

#[async_trait]
impl ConsentRepository for TessaridbConsentRepository {
    async fn create(&self, place: &Place, id: &str, consent: &ConsentEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE consents:$id = { tenant: $tenant, user_id: $user_id, client_id: $client_id, \
                 scopes: $scopes, resources: $resources, policy_version: $policy_version, \
                 shown_version: $shown_version, granted_at: $granted_at, revision: $revision };",
                grant_values(id, consent),
            )
            .await?;
        Ok(())
    }

    async fn replace(
        &self,
        place: &Place,
        id: &str,
        consent: &ConsentEntity,
        seen: i64,
    ) -> Result<()> {
        let mut values = grant_values(id, consent);
        values.push(("seen".to_owned(), Value::from(seen)));
        self.database
            .run_at(
                place,
                "UPDATE consents:$id SET scopes = $scopes, resources = $resources, \
                 policy_version = $policy_version, shown_version = $shown_version, granted_at = $granted_at, \
                 revision = $revision, revoked_at = NONE, revoked_by = NONE WHERE revision = $seen;",
                values,
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, id: &str) -> Result<Option<ConsentEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM consents:$id;",
                vec![("id".to_owned(), text(id))],
            )
            .await?;
        answers::single(answers, "consent")
    }

    async fn list_for_user(&self, place: &Place, user_id: &str) -> Result<Vec<ConsentEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM consents WHERE user_id = $user_id;",
                vec![("user_id".to_owned(), text(user_id))],
            )
            .await?;
        answers::records(answers, "consent")
    }

    async fn revoke(
        &self,
        place: &Place,
        id: &str,
        at: i64,
        by: &str,
    ) -> Result<Option<ConsentEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "UPDATE consents:$id SET revoked_at = $at, revoked_by = $by WHERE revoked_at = NONE RETURN BEFORE;",
                vec![
                    ("id".to_owned(), text(id)),
                    ("at".to_owned(), Value::from(at)),
                    ("by".to_owned(), text(by)),
                ],
            )
            .await?;
        answers::returned(answers, id, "consent")
    }
}
