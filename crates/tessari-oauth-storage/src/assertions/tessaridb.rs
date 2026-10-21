//! Spent assertions on TessariDB: a space whose keys expire, written by one conditional `SET`.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Answer, Database, Place, Value};

use super::repository::AssertionRepository;
use crate::{Error, Result};

pub(crate) struct TessaridbAssertionRepository {
    database: Database,
}

impl TessaridbAssertionRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl AssertionRepository for TessaridbAssertionRepository {
    async fn record_if_absent(&self, place: &Place, key: &str, seconds: u64) -> Result<bool> {
        let seconds = i64::try_from(seconds).map_err(|_| Error::Unreadable {
            record: "assertion",
            reason: "a retention beyond i64 seconds".to_owned(),
        })?;
        // `IF ABSENT` reads and writes the key in one transaction and answers whether it wrote, so of two
        // simultaneous presentations exactly one is told `true`. The expiry is written into the same version.
        let answers = self
            .database
            .run_at(
                place,
                "SET assertions:$key = true IF ABSENT EXPIRE duration::from_secs($seconds);",
                vec![
                    ("key".to_owned(), Value::from(key)),
                    ("seconds".to_owned(), Value::from(seconds)),
                ],
            )
            .await?;
        match answers.into_iter().next() {
            Some(Answer::Value {
                value: Value::Bool(written),
                ..
            }) => Ok(written),
            _ => Err(Error::Unreadable {
                record: "assertion",
                reason: "a conditional SET answered something other than whether it wrote"
                    .to_owned(),
            }),
        }
    }
}
