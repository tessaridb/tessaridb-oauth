//! A company's brand: absent until set, read back as set and replaced whole; its logo is kept apart from it, read
//! back byte for byte, replaced and removed; and one company's brand is never another's.

use tessari_oauth_core::branding::{Accent, BrandLink, BrandName};
use tessari_oauth_core::logo::{Png, reencode};
use tessari_oauth_storage::brands::Brand;
use tessari_oauth_types::{TenantId, Timestamp};

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn brand(name: &str, accent: &str, support: Option<&str>) -> Brand {
    Brand {
        name: BrandName::parse(name).expect("a name"),
        accent: Accent::parse(accent).expect("an accent"),
        support: support.map(|link| BrandLink::parse(link).expect("a link")),
        privacy: None,
        updated_at: NOW,
    }
}

/// A one-pixel PNG of `shade`, re-encoded as the server keeps it.
fn logo(shade: u8) -> Png {
    let mut sent = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut sent, 1, 1);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("a header");
        writer
            .write_image_data(&[shade, shade, shade, 255])
            .expect("a pixel");
    }
    reencode(&sent).expect("a logo")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_brand_is_absent_until_set_and_is_replaced_whole() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let brands = &storage.brands;
    assert_eq!(brands.find(&acme).await, Ok(None));
    let first = brand("Acme Bank", "#1f4fd8", Some("https://help.acme.example/"));
    brands.set(&acme, &first).await.expect("set");
    assert_eq!(brands.find(&acme).await, Ok(Some(first)));
    let second = brand("Acme", "#000000", None);
    brands.set(&acme, &second).await.expect("set again");
    assert_eq!(
        brands.find(&acme).await,
        Ok(Some(second)),
        "the support link set first is gone with the replacement"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_logo_is_kept_apart_read_back_byte_for_byte_replaced_and_removed() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let brands = &storage.brands;
    assert_eq!(brands.logo(&acme).await, Ok(None));
    assert_eq!(brands.logo_updated(&acme).await, Ok(None));
    let dark = logo(0);
    brands
        .set_logo(&acme, &dark, NOW)
        .await
        .expect("a logo set");
    assert_eq!(
        brands.logo(&acme).await.expect("read").as_deref(),
        Some(dark.as_bytes())
    );
    assert_eq!(brands.logo_updated(&acme).await, Ok(Some(NOW)));
    assert_eq!(brands.find(&acme).await, Ok(None), "a logo sets no brand");
    let later = Timestamp::from_unix_secs(1_800_000_060);
    let light = logo(250);
    brands
        .set_logo(&acme, &light, later)
        .await
        .expect("replaced");
    assert_eq!(
        brands.logo(&acme).await.expect("read").as_deref(),
        Some(light.as_bytes())
    );
    assert_eq!(brands.logo_updated(&acme).await, Ok(Some(later)));
    assert_eq!(brands.remove_logo(&acme).await, Ok(true));
    assert_eq!(
        brands.remove_logo(&acme).await,
        Ok(false),
        "nothing left to remove"
    );
    assert_eq!(brands.logo(&acme).await, Ok(None));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn another_company_never_sees_a_brand_or_a_logo() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let globex = tenant("globex");
    storage
        .tenants
        .provision(&globex)
        .await
        .expect("a second company");
    let brands = &storage.brands;
    brands
        .set(&acme, &brand("Acme Bank", "#1f4fd8", None))
        .await
        .expect("set");
    brands.set_logo(&acme, &logo(0), NOW).await.expect("logo");
    assert_eq!(brands.find(&globex).await, Ok(None));
    assert_eq!(brands.logo(&globex).await, Ok(None));
    assert_eq!(brands.remove_logo(&globex).await, Ok(false));
    assert!(brands.logo(&acme).await.expect("read").is_some());
}
