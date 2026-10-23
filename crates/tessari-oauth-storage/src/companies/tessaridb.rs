//! The directory on TessariDB: the `companies` table and the one-record `region` table in the region's `directory`
//! database.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::CompanyEntity;
use super::entity::{ListedEntity, RegionEntity};
use super::repository::CompanyRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbCompanyRepository {
    database: Database,
}

impl TessaridbCompanyRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl CompanyRepository for TessaridbCompanyRepository {
    async fn prepare(&self, place: &Place) -> Result<()> {
        // Names are checked plain by `Place`, which is what allows them into the text.
        let namespace = place.namespace();
        let database = place.database();
        let script = format!(
            "DEFINE NAMESPACE IF NOT EXISTS {namespace}; USE NAMESPACE {namespace}; \
             DEFINE DATABASE IF NOT EXISTS {database}; USE DATABASE {database}; \
             DEFINE TABLE IF NOT EXISTS companies (\
             name string REQUIRED, \
             status string REQUIRED ASSERT $value IN ['provisioning', 'active', 'suspended'], \
             created_at int REQUIRED, created_by string REQUIRED); \
             DEFINE TABLE IF NOT EXISTS region (base_url string REQUIRED);"
        );
        self.database.run_unplaced(&script, Vec::new()).await?;
        Ok(())
    }

    async fn create(&self, place: &Place, id: &str, company: &CompanyEntity) -> Result<()> {
        // `CREATE` refuses an id that exists, so two operators creating one id leave one company.
        self.database
            .run_at(
                place,
                "CREATE companies:$id = { name: $name, status: $status, created_at: $created_at, \
                 created_by: $created_by };",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("name".to_owned(), Value::from(company.name.as_str())),
                    ("status".to_owned(), Value::from(company.status.as_str())),
                    ("created_at".to_owned(), Value::from(company.created_at)),
                    (
                        "created_by".to_owned(),
                        Value::from(company.created_by.as_str()),
                    ),
                ],
            )
            .await?;
        Ok(())
    }

    async fn find(&self, place: &Place, id: &str) -> Result<Option<CompanyEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM companies:$id;",
                vec![("id".to_owned(), Value::from(id))],
            )
            .await?;
        answers::single(answers, "company")
    }

    async fn page(
        &self,
        place: &Place,
        after: Option<&str>,
        count: u32,
    ) -> Result<Vec<ListedEntity>> {
        let count = Value::from(i64::from(count));
        let answers = match after {
            Some(after) => {
                self.database
                    .run_at(
                        place,
                        "SELECT * FROM companies AFTER companies:$after LIMIT $count;",
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
                        "SELECT * FROM companies LIMIT $count;",
                        vec![("count".to_owned(), count)],
                    )
                    .await?
            }
        };
        answers::records(answers, "company")
    }

    async fn transition(&self, place: &Place, id: &str, from: &str, to: &str) -> Result<()> {
        // The `WHERE` on an `UPDATE` is a compare-and-set: a company not in `from` is refused and nothing is written.
        self.database
            .run_at(
                place,
                "UPDATE companies:$id SET status = $to WHERE status = $from;",
                vec![
                    ("id".to_owned(), Value::from(id)),
                    ("from".to_owned(), Value::from(from)),
                    ("to".to_owned(), Value::from(to)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn record_base(&self, place: &Place, base_url: &str) -> Result<()> {
        // The record is the whole of what the region says about itself, so replacing it is the write meant.
        self.database
            .run_at(
                place,
                "UPSERT region:'base' = { base_url: $base_url };",
                vec![("base_url".to_owned(), Value::from(base_url))],
            )
            .await?;
        Ok(())
    }

    async fn base(&self, place: &Place) -> Result<Option<RegionEntity>> {
        let answers = self
            .database
            .run_at(place, "SELECT * FROM region:'base';", Vec::new())
            .await?;
        answers::single(answers, "region")
    }
}
