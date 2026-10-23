//! The `mail_defaults` and `mail_templates` rows exactly as stored, each under the id of its mail kind.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// A mail's wording as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateEntity {
    /// The record id as the node spelled it.
    pub spelled: String,
    /// The subject.
    pub subject: String,
    /// The text.
    pub text: String,
    /// Unix seconds of the last change.
    pub updated_at: i64,
    /// Who set it, for a company's override; none for a default.
    pub updated_by: Option<String>,
    /// How many times a company set its own wording for the kind: 1 for the first; 0 for a default.
    pub revision: i64,
}

impl FromRecord for TemplateEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            spelled: row.id().to_owned(),
            subject: row.take("subject")?,
            text: row.take("text")?,
            updated_at: row.take("updated_at")?,
            updated_by: row.take("updated_by")?,
            revision: row.take::<Option<i64>>("revision")?.unwrap_or(0),
        })
    }
}
