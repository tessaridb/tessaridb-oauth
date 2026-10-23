//! The `brand` and `brand_logo` rows exactly as stored, each under the id `current`.

use tessari_oauth_infrastructure::tessaridb::{FromRecord, MappingFault, Row};

/// A company's brand as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrandEntity {
    /// The display name.
    pub name: String,
    /// The accent colour, `#rrggbb`.
    pub accent: String,
    /// The support link, when one is set.
    pub support_url: Option<String>,
    /// The privacy link, when one is set.
    pub privacy_url: Option<String>,
    /// Unix seconds of the last change.
    pub updated_at: i64,
}

impl FromRecord for BrandEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            name: row.take("name")?,
            accent: row.take("accent")?,
            support_url: row.take("support_url")?,
            privacy_url: row.take("privacy_url")?,
            updated_at: row.take("updated_at")?,
        })
    }
}

/// A company's logo as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoEntity {
    /// The PNG this server wrote, base64url.
    pub png: String,
    /// Unix seconds of the upload.
    pub updated_at: i64,
}

impl FromRecord for LogoEntity {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            png: row.take("png")?,
            updated_at: row.take("updated_at")?,
        })
    }
}

/// When a company's logo was uploaded, read without the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogoStamp {
    /// Unix seconds of the upload.
    pub updated_at: i64,
}

impl FromRecord for LogoStamp {
    fn from_row(mut row: Row) -> Result<Self, MappingFault> {
        Ok(Self {
            updated_at: row.take("updated_at")?,
        })
    }
}
