//! Signing keys on TessariDB.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::KeyEntity;
use super::repository::KeyRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbKeyRepository {
    database: Database,
}

impl TessaridbKeyRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn text(value: &str) -> Value {
    Value::from(value)
}

#[async_trait]
impl KeyRepository for TessaridbKeyRepository {
    async fn create(&self, place: &Place, key: &KeyEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE signing_keys:$kid = { kid: $kid, tenant: $tenant, algorithm: $algorithm, sealed: $sealed, \
                 public_jwk: $public_jwk, created_at: $created_at, compromised: false };",
                vec![
                    ("kid".to_owned(), text(&key.kid)),
                    ("tenant".to_owned(), text(&key.tenant)),
                    ("algorithm".to_owned(), text(&key.algorithm)),
                    ("sealed".to_owned(), text(&key.sealed)),
                    ("public_jwk".to_owned(), text(&key.public_jwk)),
                    ("created_at".to_owned(), Value::from(key.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn live(&self, place: &Place) -> Result<Vec<KeyEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM signing_keys WHERE retired_at = NONE ORDER BY created_at;",
                Vec::new(),
            )
            .await?;
        answers::records(answers, "signing key")
    }

    async fn retire(&self, place: &Place, kid: &str, at: i64) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPDATE signing_keys:$kid SET retired_at = $at WHERE retired_at = NONE;",
                vec![
                    ("kid".to_owned(), text(kid)),
                    ("at".to_owned(), Value::from(at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn compromise(&self, place: &Place, kid: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPDATE signing_keys:$kid SET compromised = true;",
                vec![("kid".to_owned(), text(kid))],
            )
            .await?;
        Ok(())
    }
}
