//! Address changes on TessariDB: the `email_changes` table, whose records expire on their own after two days.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::EmailChangeEntity;
use super::repository::EmailChangeRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbEmailChangeRepository {
    database: Database,
}

impl TessaridbEmailChangeRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl EmailChangeRepository for TessaridbEmailChangeRepository {
    async fn issue(&self, place: &Place, digest: &str, entity: &EmailChangeEntity) -> Result<()> {
        // A user holds one pending change: a newer request removes the earlier one in the same commit.
        self.database
            .run_at(
                place,
                "BEGIN; DELETE FROM email_changes WHERE user_id = $user LIMIT ALL; \
                 CREATE email_changes:$digest = { user_id: $user, old_address: $old, new_address: $new, \
                 cancel_digest: $cancel, created_at: $created_at }; COMMIT;",
                vec![
                    ("user".to_owned(), Value::from(entity.user_id.as_str())),
                    ("old".to_owned(), Value::from(entity.old_address.as_str())),
                    ("new".to_owned(), Value::from(entity.new_address.as_str())),
                    ("cancel".to_owned(), Value::from(entity.cancel_digest.as_str())),
                    ("digest".to_owned(), Value::from(digest)),
                    ("created_at".to_owned(), Value::from(entity.created_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn confirm(
        &self,
        place: &Place,
        digest: &str,
        now: i64,
        since: i64,
    ) -> Result<Option<EmailChangeEntity>> {
        // A condition on an edit is a compare-and-set: two confirmations racing see the record unconfirmed once.
        let answers = self
            .database
            .run_at(
                place,
                "UPDATE email_changes:$digest SET confirmed_at = $now \
                 WHERE confirmed_at = NONE AND created_at >= $since RETURN AFTER;",
                vec![
                    ("digest".to_owned(), Value::from(digest)),
                    ("now".to_owned(), Value::from(now)),
                    ("since".to_owned(), Value::from(since)),
                ],
            )
            .await?;
        answers::returned(answers, digest, "address change")
    }

    async fn cancel(&self, place: &Place, cancel: &str) -> Result<Option<EmailChangeEntity>> {
        // One delete that answers what it removed: two cancellations racing see the record once.
        let answers = self
            .database
            .run_at(
                place,
                "DELETE FROM email_changes WHERE cancel_digest = $cancel LIMIT 1 RETURN BEFORE;",
                vec![("cancel".to_owned(), Value::from(cancel))],
            )
            .await?;
        Ok(answers::records(answers, "address change")?.pop())
    }

    async fn due(&self, place: &Place, before: i64, limit: u32) -> Result<Vec<EmailChangeEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM email_changes WHERE confirmed_at != NONE AND created_at <= $before LIMIT $limit;",
                vec![
                    ("before".to_owned(), Value::from(before)),
                    ("limit".to_owned(), Value::from(i64::from(limit))),
                ],
            )
            .await?;
        answers::records(answers, "address change")
    }

    async fn apply(
        &self,
        place: &Place,
        id: &str,
        user_id: &str,
        (old, new): (&str, &str),
        verified_at: i64,
    ) -> Result<()> {
        // A delete by id takes no condition, so each one is guarded by a compare-and-set on the same record that
        // changes nothing: it refuses a change no longer confirmed as it was read, or an old address that is no longer
        // this user's. `CREATE` refuses an address another account holds. Any refusal discards the whole transaction.
        self.database
            .run_at(
                place,
                "BEGIN; \
                 UPDATE email_changes:$id SET confirmed_at = $verified_at WHERE confirmed_at = $verified_at; \
                 DELETE email_changes:$id; \
                 UPDATE user_emails:$old SET user_id = $user WHERE user_id = $user; \
                 DELETE user_emails:$old; \
                 CREATE user_emails:$new = { address: $new, user_id: $user, verified_at: $verified_at, \
                 verified_by: $by }; COMMIT;",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("user".to_owned(), Value::from(user_id)),
                    ("old".to_owned(), Value::from(old)),
                    ("new".to_owned(), Value::from(new)),
                    ("verified_at".to_owned(), Value::from(verified_at)),
                    ("by".to_owned(), Value::from("mail")),
                ],
            )
            .await?;
        Ok(())
    }

    async fn discard(&self, place: &Place, id: &str) -> Result<()> {
        self.database
            .run_at(
                place,
                "DELETE email_changes:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        Ok(())
    }
}
