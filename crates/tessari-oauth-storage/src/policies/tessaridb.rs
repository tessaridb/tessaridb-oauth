//! Policies on TessariDB: `two_factor:policy`, one record per company database.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::PolicyEntity;
use super::repository::PolicyRepository;
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
}
