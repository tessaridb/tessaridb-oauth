//! Policies on TessariDB: `two_factor:policy` and `registration:policy`, one record each per company database.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::repository::PolicyRepository;
use super::{PolicyEntity, RegistrationEntity};
use crate::{Result, answers};

pub(crate) struct TessaridbPolicyRepository {
    database: Database,
}

impl TessaridbPolicyRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl PolicyRepository for TessaridbPolicyRepository {
    async fn find_two_factor(&self, place: &Place) -> Result<Option<PolicyEntity>> {
        let answers = self
            .database
            .run_at(place, "SELECT * FROM two_factor:'policy';", Vec::new())
            .await?;
        answers::single(answers, "two-factor policy")
    }

    async fn put_two_factor(&self, place: &Place, policy: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPSERT two_factor:'policy' = { policy: $policy };",
                vec![("policy".to_owned(), Value::from(policy))],
            )
            .await?;
        Ok(())
    }

    async fn create_two_factor(&self, place: &Place, policy: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE two_factor:'policy' = { policy: $policy };",
                vec![("policy".to_owned(), Value::from(policy))],
            )
            .await?;
        Ok(())
    }

    async fn replace_two_factor(&self, place: &Place, expected: &str, policy: &str) -> Result<()> {
        // A condition on an edit is a compare-and-set: the store refuses it when the policy moved.
        self.database
            .run_at(
                place,
                "UPDATE two_factor:'policy' SET policy = $policy WHERE policy = $expected;",
                vec![
                    ("policy".to_owned(), Value::from(policy)),
                    ("expected".to_owned(), Value::from(expected)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_registration(&self, place: &Place) -> Result<Option<RegistrationEntity>> {
        let answers = self
            .database
            .run_at(place, "SELECT * FROM registration:'policy';", Vec::new())
            .await?;
        answers::single(answers, "registration policy")
    }

    async fn create_registration(&self, place: &Place, policy: &RegistrationEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE registration:'policy' = { open: $open, domains: $domains, revision: $revision };",
                registration_values(policy),
            )
            .await?;
        Ok(())
    }

    async fn replace_registration(
        &self,
        place: &Place,
        replaces: i64,
        policy: &RegistrationEntity,
    ) -> Result<()> {
        // The whole record, and only from the revision the caller read: a condition on an edit is a compare-and-set.
        let mut values = registration_values(policy);
        values.push(("replaces".to_owned(), Value::from(replaces)));
        self.database
            .run_at(
                place,
                "UPDATE registration:'policy' = { open: $open, domains: $domains, revision: $revision } \
                 WHERE revision = $replaces;",
                values,
            )
            .await?;
        Ok(())
    }
}

/// The values every write of a registration policy binds.
fn registration_values(policy: &RegistrationEntity) -> Vec<(String, Value)> {
    vec![
        ("open".to_owned(), Value::from(policy.open)),
        (
            "domains".to_owned(),
            Value::Array(
                policy
                    .domains
                    .iter()
                    .map(|domain| Value::from(domain.as_str()))
                    .collect(),
            ),
        ),
        ("revision".to_owned(), Value::from(policy.revision)),
    ]
}
