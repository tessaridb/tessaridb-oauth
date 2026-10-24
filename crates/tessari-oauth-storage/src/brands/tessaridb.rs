//! Brands on TessariDB: `brand:current` and `brand_logo:current`, one of each per company database.

use async_trait::async_trait;
use tessari_oauth_infrastructure::tessaridb::{Database, Place, Value};

use super::entity::LogoStamp;
use super::repository::BrandRepository;
use super::{BrandEntity, LogoEntity};
use crate::{Result, answers};

pub(crate) struct TessaridbBrandRepository {
    database: Database,
}

/// The values a brand is written with; a link left out of the brand is written as no field at all.
fn values(brand: &BrandEntity) -> Vec<(String, Value)> {
    vec![
        ("name".to_owned(), Value::from(brand.name.as_str())),
        ("accent".to_owned(), Value::from(brand.accent.as_str())),
        (
            "support".to_owned(),
            brand
                .support_url
                .as_deref()
                .map_or(Value::None, Value::from),
        ),
        (
            "privacy".to_owned(),
            brand
                .privacy_url
                .as_deref()
                .map_or(Value::None, Value::from),
        ),
        ("at".to_owned(), Value::from(brand.updated_at)),
        ("revision".to_owned(), Value::from(brand.revision)),
    ]
}

impl TessaridbBrandRepository {
    pub(crate) const fn new(database: Database) -> Self {
        Self { database }
    }
}

#[async_trait]
impl BrandRepository for TessaridbBrandRepository {
    async fn find(&self, place: &Place) -> Result<Option<BrandEntity>> {
        let answers = self
            .database
            .run_at(place, "SELECT * FROM brand:'current';", Vec::new())
            .await?;
        answers::single(answers, "brand")
    }

    async fn create(&self, place: &Place, brand: &BrandEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "CREATE brand:'current' = { name: $name, accent: $accent, support_url: $support, \
                 privacy_url: $privacy, updated_at: $at, revision: $revision };",
                values(brand),
            )
            .await?;
        Ok(())
    }

    async fn replace(&self, place: &Place, replaces: i64, brand: &BrandEntity) -> Result<()> {
        // The whole record, and only from the revision the caller read: a condition on an edit is a compare-and-set.
        let mut values = values(brand);
        values.push(("replaces".to_owned(), Value::from(replaces)));
        self.database
            .run_at(
                place,
                "UPDATE brand:'current' = { name: $name, accent: $accent, support_url: $support, \
                 privacy_url: $privacy, updated_at: $at, revision: $revision } WHERE revision = $replaces;",
                values,
            )
            .await?;
        Ok(())
    }

    async fn find_logo(&self, place: &Place) -> Result<Option<LogoEntity>> {
        let answers = self
            .database
            .run_at(place, "SELECT * FROM brand_logo:'current';", Vec::new())
            .await?;
        answers::single(answers, "brand logo")
    }

    async fn logo_stamp(&self, place: &Place) -> Result<Option<LogoStamp>> {
        let answers = self
            .database
            .run_at(
                place,
                "SELECT updated_at FROM brand_logo:'current';",
                Vec::new(),
            )
            .await?;
        answers::single(answers, "brand logo")
    }

    async fn put_logo(&self, place: &Place, logo: &LogoEntity) -> Result<()> {
        self.database
            .run_at(
                place,
                "UPSERT brand_logo:'current' = { png: $png, updated_at: $at };",
                vec![
                    ("png".to_owned(), Value::from(logo.png.as_str())),
                    ("at".to_owned(), Value::from(logo.updated_at)),
                ],
            )
            .await?;
        Ok(())
    }

    async fn delete_logo(&self, place: &Place) -> Result<bool> {
        let answers = self
            .database
            .run_at(
                place,
                "DELETE brand_logo:'current' RETURN BEFORE;",
                Vec::new(),
            )
            .await?;
        Ok(answers::returned::<LogoEntity>(answers, "current", "brand logo")?.is_some())
    }
}
