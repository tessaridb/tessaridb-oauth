//! What the brand service needs from a backend.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::Place;

use super::entity::LogoStamp;
use super::{BrandEntity, LogoEntity};
use crate::Result;

/// Reads and writes a company's brand and logo.
#[async_trait]
pub(crate) trait BrandRepository: Send + Sync {
    /// The stored brand, when one was ever set.
    async fn find(&self, place: &Place) -> Result<Option<BrandEntity>>;

    /// Store `brand` where none is stored; refused as a conflict when one is.
    async fn create(&self, place: &Place, brand: &BrandEntity) -> Result<()>;

    /// Replace the stored brand whole with `brand` only while it is at revision `replaces`; refused as a conflict
    /// otherwise.
    async fn replace(&self, place: &Place, replaces: i64, brand: &BrandEntity) -> Result<()>;

    /// The stored logo, when one is set.
    async fn find_logo(&self, place: &Place) -> Result<Option<LogoEntity>>;

    /// When the stored logo was uploaded, without reading the image.
    async fn logo_stamp(&self, place: &Place) -> Result<Option<LogoStamp>>;

    /// Store `logo`, replacing any before.
    async fn put_logo(&self, place: &Place, logo: &LogoEntity) -> Result<()>;

    /// Remove the logo; whether there was one.
    async fn delete_logo(&self, place: &Place) -> Result<bool>;
}
