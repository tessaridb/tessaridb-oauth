//! Sealed values on TessariDB. A table name is grammar and is never bound: it comes from [`Family`], never from a
//! caller.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::entity::SealedEntity;
use super::model::Family;
use super::repository::SealedRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbSealedRepository {
    database: Database,
}

impl TessaridbSealedRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl SealedRepository for TessaridbSealedRepository {
    async fn page(
        &self,
        place: &Place,
        family: Family,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<SealedEntity>> {
        let table = family.table();
        let count = Value::from(i64::from(count));
        let answers = match after {
            Some(after) => {
                self.database
                    .run_at(
                        place,
                        &format!("SELECT * FROM {table} AFTER {table}:$after LIMIT $count;"),
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
                        &format!("SELECT * FROM {table} LIMIT $count;"),
                        vec![("count".to_owned(), count)],
                    )
                    .await?
            }
        };
        answers::records(answers, "sealed value")
    }

    async fn replace(
        &self,
        place: &Place,
        family: Family,
        id: &str,
        old: &str,
        new: &str,
    ) -> Result<()> {
        let table = family.table();
        // The condition makes the write a compare-and-set: a value changed since it was read is refused, not lost.
        self.database
            .run_at(
                place,
                &format!("UPDATE {table}:$id SET sealed = $new WHERE sealed = $old;"),
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("old".to_owned(), Value::from(old)),
                    ("new".to_owned(), Value::from(new)),
                ],
            )
            .await?;
        Ok(())
    }
}
