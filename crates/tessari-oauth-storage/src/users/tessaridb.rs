//! Users on TessariDB: `users:<id>`, `user_emails:<address>` and `credentials:<id>`.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::repository::UserRepository;
use super::{CredentialEntity, EmailEntity, UserEntity};
use crate::{Result, answers};

pub(crate) struct TessaridbUserRepository {
    database: Database,
}

impl TessaridbUserRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl UserRepository for TessaridbUserRepository {
    async fn create(&self, place: &Place, user: &UserEntity, email: &EmailEntity) -> Result<()> {
        // `CREATE` refuses an id that exists, so an address belongs to one account: the address is written first,
        // and its refusal discards the transaction before the account is written.
        self.database
            .run_at(
                place,
                "BEGIN; \
                 CREATE user_emails:$address = { address: $address, user_id: $id }; \
                 CREATE users:$id = { user_id: $id, tenant: $tenant, status: $status, created_at: $created_at }; \
                 COMMIT;",
                vec![
                    ("address".to_owned(), Value::from(email.address.as_str())),
                    ("id".to_owned(), Value::from(user.user_id.as_str())),
                    ("tenant".to_owned(), Value::from(user.tenant.as_str())),
                    ("status".to_owned(), Value::from(user.status.as_str())),
                    ("created_at".to_owned(), Value::from(user.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_email(&self, place: &Place, address: &str) -> Result<Option<EmailEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM user_emails:$address;",
                vec![("address".to_owned(), Value::from(address))],
            )
            .await?;
        answers::single(answers, "user email")
    }

    async fn find_user(&self, place: &Place, user_id: &str) -> Result<Option<UserEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM users:$id;",
                vec![("id".to_owned(), Value::from(user_id))],
            )
            .await?;
        answers::single(answers, "user")
    }

    async fn find_email_of(&self, place: &Place, user_id: &str) -> Result<Option<EmailEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM user_emails WHERE user_id = $user USING INDEX by_user;",
                vec![("user".to_owned(), Value::from(user_id))],
            )
            .await?;
        answers::single(answers, "user email")
    }

    async fn put_credential(&self, place: &Place, credential: &CredentialEntity) -> Result<()> {
        // The record is the credential, so it is replaced whole.
        self.database
            .run_at(
                place,
                "UPSERT credentials:$id = { user_id: $id, hash: $hash, pepper: $pepper, \
                 updated_at: $updated_at };",
                vec![
                    ("id".to_owned(), Value::from(credential.user_id.as_str())),
                    ("hash".to_owned(), Value::from(credential.hash.as_str())),
                    ("pepper".to_owned(), Value::from(credential.pepper)),
                    ("updated_at".to_owned(), Value::from(credential.updated_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find_credential(
        &self,
        place: &Place,
        user_id: &str,
    ) -> Result<Option<CredentialEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM credentials:$id;",
                vec![("id".to_owned(), Value::from(user_id))],
            )
            .await?;
        answers::single(answers, "credential")
    }

    async fn page(
        &self,
        place: &Place,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<UserEntity>> {
        let count = Value::from(i64::from(count));
        let answers = match after {
            Some(after) => {
                self.database
                    .run_at(
                        place,
                        "SELECT * FROM users AFTER users:$after LIMIT $count;",
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
                        "SELECT * FROM users LIMIT $count;",
                        vec![("count".to_owned(), count)],
                    )
                    .await?
            }
        };
        answers::records(answers, "user")
    }

    async fn emails_of(&self, place: &Place, user_ids: &[String]) -> Result<Vec<EmailEntity>> {
        // One read for the whole page, bounded by it: never one read per listed account.
        let count = i64::try_from(user_ids.len()).map_err(|_| crate::Error::Invalid {
            record: "user page",
            reason: "more accounts than a count can hold",
        })?;
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM user_emails WHERE user_id IN $ids LIMIT $count;",
                vec![
                    (
                        "ids".to_owned(),
                        Value::Array(user_ids.iter().map(|id| Value::from(id.as_str())).collect()),
                    ),
                    ("count".to_owned(), Value::from(count)),
                ],
            )
            .await?;
        answers::records(answers, "user email")
    }

    async fn set_status(&self, place: &Place, user_id: &str, from: &str, to: &str) -> Result<()> {
        // A condition on an edit is a compare-and-set: the store refuses it when the status moved.
        self.database
            .run_at(
                place,
                "UPDATE users:$id SET status = $to WHERE status = $from;",
                vec![
                    ("id".to_owned(), Value::from(user_id)),
                    ("from".to_owned(), Value::from(from)),
                    ("to".to_owned(), Value::from(to)),
                ],
            )
            .await?;
        Ok(())
    }
}
