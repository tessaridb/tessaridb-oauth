//! Mail templates on TessariDB: `mail_defaults:<kind>` in the region's `mail` database, `mail_templates:<kind>` in
//! each company's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::TemplateEntity;
use super::repository::MailTemplateRepository;
use crate::{Result, answers};

pub(crate) struct TessaridbMailTemplateRepository {
    database: Database,
}

impl TessaridbMailTemplateRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

/// The values a default is written with.
fn values(kind: &str, template: &TemplateEntity) -> Vec<(String, Value)> {
    vec![
        ("kind".to_owned(), Value::from(kind)),
        ("subject".to_owned(), Value::from(template.subject.as_str())),
        ("text".to_owned(), Value::from(template.text.as_str())),
        ("at".to_owned(), Value::from(template.updated_at)),
    ]
}

#[async_trait]
impl MailTemplateRepository for TessaridbMailTemplateRepository {
    async fn prepare(&self, place: &Place) -> Result<()> {
        // Names are checked plain by `Place`, which is what allows them into the text.
        let namespace = place.namespace();
        let database = place.database();
        let script = format!(
            "DEFINE NAMESPACE IF NOT EXISTS {namespace}; USE NAMESPACE {namespace}; \
             DEFINE DATABASE IF NOT EXISTS {database}; USE DATABASE {database}; \
             DEFINE TABLE IF NOT EXISTS mail_defaults (\
             subject string REQUIRED, text string REQUIRED, updated_at int REQUIRED);"
        );
        self.database.run_unplaced(&script, Vec::new()).await?;
        Ok(())
    }

    async fn create_default(
        &self,
        place: &Place,
        kind: &str,
        template: &TemplateEntity,
    ) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE mail_defaults:$kind = { subject: $subject, text: $text, updated_at: $at };",
                values(kind, template),
            )
            .await?;
        Ok(())
    }

    async fn find_default(&self, place: &Place, kind: &str) -> Result<Option<TemplateEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM mail_defaults:$kind;",
                vec![("kind".to_owned(), Value::from(kind))],
            )
            .await?;
        answers::single(answers, "mail default")
    }

    async fn find_override(&self, place: &Place, kind: &str) -> Result<Option<TemplateEntity>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT * FROM mail_templates:$kind;",
                vec![("kind".to_owned(), Value::from(kind))],
            )
            .await?;
        answers::single(answers, "mail template")
    }

    async fn overrides(&self, place: &Place) -> Result<Vec<TemplateEntity>> {
        // One row per kind at most, and there are nine kinds.
        let answers = self
            .database
            .run_at(place, "SELECT * FROM mail_templates LIMIT 50;", Vec::new())
            .await?;
        answers::records(answers, "mail template")
    }

    async fn put_override(
        &self,
        place: &Place,
        kind: &str,
        template: &TemplateEntity,
    ) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPSERT mail_templates:$kind = { subject: $subject, text: $text, updated_at: $at, \
                 updated_by: $by };",
                {
                    let mut values = values(kind, template);
                    let by = template
                        .updated_by
                        .as_deref()
                        .map_or(Value::None, Value::from);
                    values.push(("by".to_owned(), by));
                    values
                },
            )
            .await?;
        Ok(())
    }

    async fn delete_override(&self, place: &Place, kind: &str) -> Result<bool> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE mail_templates:$kind RETURN BEFORE;",
                vec![("kind".to_owned(), Value::from(kind))],
            )
            .await?;
        Ok(answers::returned::<TemplateEntity>(answers, kind, "mail template")?.is_some())
    }
}
