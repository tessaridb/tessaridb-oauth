//! Codes on TessariDB.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Answer, Database, FromRecord, Place, Row, Value};

use super::CodeEntity;
use super::repository::CodeRepository;
use crate::{Error, Result};

pub(crate) struct TessaridbCodeRepository {
    database: Database,
}

impl TessaridbCodeRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

fn text(value: &str) -> Value {
    Value::from(value)
}

/// The one record a statement addressed by id answered with, if any.
fn single(answers: Vec<Answer>) -> Result<Option<CodeEntity>> {
    let Some(answer) = answers.into_iter().next() else {
        return Ok(None);
    };
    let mut rows = answer
        .records_into::<CodeEntity>()
        .map_err(|fault| Error::Unreadable {
            record: "code",
            reason: fault.to_string(),
        })?;
    Ok(rows.pop())
}

/// The record a `RETURN BEFORE` answered with: one value rather than a set of records, so it is opened as a row
/// under the digest it was addressed by.
fn before(answers: Vec<Answer>, digest: &str) -> Result<Option<CodeEntity>> {
    let unreadable = |reason: String| Error::Unreadable {
        record: "code",
        reason,
    };
    match answers.into_iter().next() {
        Some(Answer::Value { value, .. }) => {
            let row = Row::new(digest.to_owned(), value)
                .map_err(|fault| unreadable(fault.to_string()))?;
            CodeEntity::from_row(row)
                .map(Some)
                .map_err(|fault| unreadable(fault.to_string()))
        }
        Some(_) => Err(unreadable(
            "a spend answered something other than the record before it".to_owned(),
        )),
        None => Ok(None),
    }
}

#[async_trait]
impl CodeRepository for TessaridbCodeRepository {
    async fn create(&self, place: &Place, digest: &str, code: &CodeEntity) -> Result<()> {
        let scopes = Value::Array(code.scopes.iter().map(|scope| text(scope)).collect());
        self.database
            .run_at(
                place,
                "CREATE codes:$id = { tenant: $tenant, client_id: $client_id, redirect_uri: $redirect_uri, \
                 challenge: $challenge, scopes: $scopes, expires_at: $expires_at };",
                vec![
                    ("id".to_owned(), text(digest)),
                    ("tenant".to_owned(), text(&code.tenant)),
                    ("client_id".to_owned(), text(&code.client_id)),
                    ("redirect_uri".to_owned(), text(&code.redirect_uri)),
                    ("challenge".to_owned(), text(&code.challenge)),
                    ("scopes".to_owned(), scopes),
                    ("expires_at".to_owned(), Value::from(code.expires_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, digest: &str) -> Result<Option<CodeEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM codes:$id;",
                vec![("id".to_owned(), text(digest))],
            )
            .await?;
        single(answers)
    }

    async fn mark_redeemed(
        &self,
        place: &Place,
        digest: &str,
        at: i64,
    ) -> Result<Option<CodeEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "UPDATE codes:$id SET redeemed_at = $at WHERE redeemed_at = NONE RETURN BEFORE;",
                vec![
                    ("id".to_owned(), text(digest)),
                    ("at".to_owned(), Value::from(at)),
                ],
            )
            .await?;
        before(answers, digest)
    }
}
