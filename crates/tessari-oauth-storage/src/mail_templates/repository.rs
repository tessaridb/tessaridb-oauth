//! What the mail-template service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::TemplateEntity;
use crate::Result;

/// Reads and writes the region's default wording and each company's overrides.
#[async_trait]
pub(crate) trait MailTemplateRepository: Send + Sync {
    /// Make the region's defaults exist; running it again changes nothing.
    async fn prepare(&self, place: &Place) -> Result<()>;

    /// Store the default for `kind` where none is stored; refused as a conflict when one is.
    async fn create_default(
        &self,
        place: &Place,
        kind: &str,
        template: &TemplateEntity,
    ) -> Result<()>;

    /// The region's default for `kind`.
    async fn find_default(&self, place: &Place, kind: &str) -> Result<Option<TemplateEntity>>;

    /// A company's override of `kind`.
    async fn find_override(&self, place: &Place, kind: &str) -> Result<Option<TemplateEntity>>;

    /// Every override a company keeps.
    async fn overrides(&self, place: &Place) -> Result<Vec<TemplateEntity>>;

    /// Store a company's override of `kind`, replacing any before.
    async fn put_override(
        &self,
        place: &Place,
        kind: &str,
        template: &TemplateEntity,
    ) -> Result<()>;

    /// Remove a company's override of `kind`; whether there was one.
    async fn delete_override(&self, place: &Place, kind: &str) -> Result<bool>;
}
