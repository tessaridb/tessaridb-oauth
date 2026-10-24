//! Mail templates on TessariDB: `mail_defaults:<kind>` in the region's `mail` database, `mail_templates:<kind>` in
//! each company's.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::TemplateEntity;
use super::repository::MailTemplateRepository;
use tessari_oauth_types::ErrorCategory;

use crate::{Result, answers};

pub(crate) struct TessaridbMailTemplateRepository {
    database: Database,
}

impl TessaridbMailTemplateRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

/// The values a company's own wording is written with.
fn own_values(kind: &str, template: &TemplateEntity) -> Vec<(String, Value)> {
    let mut values = values(kind, template);
    let by = template
        .updated_by
        .as_deref()
        .map_or(Value::None, Value::from);
    values.push(("by".to_owned(), by));
    values.push(("revision".to_owned(), Value::from(template.revision)));
    values
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

    async fn defaults(&self, place: &Place) -> Result<Vec<TemplateEntity>> {
        // One row per kind, and there are nine kinds.
        let answers = self
            .database
            .run_at(place, "SELECT * FROM mail_defaults LIMIT 50;", Vec::new())
            .await?;
        answers::records(answers, "mail default")
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

    async fn create_override(
        &self,
        place: &Place,
        kind: &str,
        template: &TemplateEntity,
    ) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE mail_templates:$kind = { subject: $subject, text: $text, updated_at: $at, \
                 updated_by: $by, revision: $revision };",
                own_values(kind, template),
            )
            .await?;
        Ok(())
    }

    async fn replace_override(
        &self,
        place: &Place,
        kind: &str,
        replaces: i64,
        template: &TemplateEntity,
    ) -> Result<bool> {
        // The whole record, and only from the revision the caller read: a condition on an edit is a compare-and-set.
        let mut values = own_values(kind, template);
        values.push(("replaces".to_owned(), Value::from(replaces)));
        let written = self
            .database
            .run_at(
                place,
                "UPDATE mail_templates:$kind = { subject: $subject, text: $text, updated_at: $at, \
                 updated_by: $by, revision: $revision } WHERE revision = $replaces;",
                values,
            )
            .await;
        moved_is_false(written.map_err(crate::Error::from))
    }

    async fn delete_override(&self, place: &Place, kind: &str, revision: i64) -> Result<bool> {
        // The compare-and-set and the delete commit together, so two resets racing remove the record once.
        let removed = self
            .database
            .run_at(
                place,
                "BEGIN; UPDATE mail_templates:$kind SET revision = $revision WHERE revision = $revision; \
                 DELETE mail_templates:$kind; COMMIT;",
                vec![
                    ("kind".to_owned(), Value::from(kind)),
                    ("revision".to_owned(), Value::from(revision)),
                ],
            )
            .await;
        moved_is_false(removed.map_err(crate::Error::from))
    }
}

/// A write's outcome: done, or not done because the record is no longer at the revision named.
fn moved_is_false<T>(written: Result<T>) -> Result<bool> {
    match written {
        Ok(_) => Ok(true),
        Err(refused) if refused.category() == ErrorCategory::Conflict => Ok(false),
        Err(failure) => Err(failure),
    }
}
