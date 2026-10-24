//! Verification tokens on TessariDB: the `address_verifications` table, whose records expire on their own after a day.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::VerificationEntity;
use super::repository::VerificationRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbVerificationRepository {
    database: Database,
}

impl TessaridbVerificationRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl VerificationRepository for TessaridbVerificationRepository {
    async fn issue(&self, place: &Place, digest: &str, entity: &VerificationEntity) -> Result<()> {
        // A user holds one live token: a newer request removes the earlier one in the same commit.
        self.database
            .run_at(
                place,
                "BEGIN; DELETE FROM address_verifications WHERE user_id = $user LIMIT ALL; \
                 CREATE address_verifications:$digest = { user_id: $user, address: $address, \
                 created_at: $created_at }; COMMIT;",
                vec![
                    ("user".to_owned(), Value::from(entity.user_id.as_str())),
                    ("address".to_owned(), Value::from(entity.address.as_str())),
                    ("digest".to_owned(), Value::from(digest)),
                    ("created_at".to_owned(), Value::from(entity.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn redeem(&self, place: &Place, digest: &str) -> Result<Option<VerificationEntity>> {
        // One delete that answers what it removed: two redemptions racing see the record once.
        let answers = self
            .database
            .run_at(
                place,
                "DELETE address_verifications:$digest RETURN BEFORE;",
                vec![("digest".to_owned(), Value::from(digest))],
            )
            .await?;
        answers::returned(answers, digest, "address verification")
    }
}
