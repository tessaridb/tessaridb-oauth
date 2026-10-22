//! The directory of companies: a company is created once under its id, in `provisioning`; it moves between statuses
//! only from the status the mover expects; the directory pages in id order from an anchor.

use tessari_oauth_storage::Storage;
use tessari_oauth_storage::companies::{CompanyStatus, Created};
use tessari_oauth_test_support::plain_node;
use tessari_oauth_types::{TenantId, Timestamp};

use crate::fresh_on;

const AT: u64 = 1_800_000_000;

fn id(raw: &str) -> TenantId {
    TenantId::parse(raw).expect("a tenant id")
}

async fn directory() -> Storage {
    let storage = fresh_on(plain_node().expect("the plain node is named"), 2);
    storage.companies.prepare().await.expect("prepared");
    storage
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_company_is_created_once_and_starts_provisioning() {
    let storage = directory().await;
    let at = Timestamp::from_unix_secs(AT);
    let made = storage
        .companies
        .create(&id("acme"), "  Acme Corp ", "user-1", at)
        .await
        .expect("an answer");
    assert_eq!(made, Created::Created);
    let again = storage
        .companies
        .create(&id("acme"), "Other", "user-2", at)
        .await
        .expect("an answer");
    assert_eq!(again, Created::Taken);
    let found = storage
        .companies
        .find(&id("acme"))
        .await
        .expect("an answer")
        .expect("the company");
    assert_eq!(found.name, "Acme Corp");
    assert_eq!(found.status, CompanyStatus::Provisioning);
    assert_eq!(found.created_by, "user-1");
    assert_eq!(found.created_at, at);
    assert!(
        storage
            .companies
            .find(&id("nobody"))
            .await
            .expect("an answer")
            .is_none()
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_name_that_is_empty_too_long_or_has_a_control_character_is_refused() {
    let storage = directory().await;
    let at = Timestamp::from_unix_secs(AT);
    for name in ["   ", &"x".repeat(101), "Acme\nCorp"] {
        assert!(
            storage
                .companies
                .create(&id("acme"), name, "user-1", at)
                .await
                .is_err(),
            "{name:?}"
        );
    }
    assert!(
        storage
            .companies
            .find(&id("acme"))
            .await
            .expect("an answer")
            .is_none()
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_status_moves_only_from_the_status_expected() {
    let storage = directory().await;
    let acme = id("acme");
    storage
        .companies
        .create(&acme, "Acme", "user-1", Timestamp::from_unix_secs(AT))
        .await
        .expect("created");
    let moved = |from, to| storage.companies.transition(&acme, from, to);
    assert!(
        !moved(CompanyStatus::Active, CompanyStatus::Suspended)
            .await
            .expect("an answer")
    );
    assert!(
        moved(CompanyStatus::Provisioning, CompanyStatus::Active)
            .await
            .expect("an answer")
    );
    assert!(
        !moved(CompanyStatus::Provisioning, CompanyStatus::Active)
            .await
            .expect("an answer")
    );
    assert!(
        moved(CompanyStatus::Active, CompanyStatus::Suspended)
            .await
            .expect("an answer")
    );
    let status = storage
        .companies
        .find(&acme)
        .await
        .expect("an answer")
        .expect("the company")
        .status;
    assert_eq!(status, CompanyStatus::Suspended);
    assert!(
        !storage
            .companies
            .transition(
                &id("nobody"),
                CompanyStatus::Active,
                CompanyStatus::Suspended
            )
            .await
            .expect("an answer for a company that does not exist")
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_directory_pages_in_id_order_from_an_anchor() {
    let storage = directory().await;
    for raw in ["delta", "alpha", "charlie", "bravo"] {
        storage
            .companies
            .create(&id(raw), raw, "user-1", Timestamp::from_unix_secs(AT))
            .await
            .expect("created");
    }
    let names = |page: Vec<tessari_oauth_storage::companies::Company>| -> Vec<String> {
        page.into_iter()
            .map(|company| company.id.as_str().to_owned())
            .collect()
    };
    let first = storage.companies.page(None, 2).await.expect("a page");
    assert_eq!(names(first), ["alpha", "bravo"]);
    let next = storage
        .companies
        .page(Some(&id("bravo")), 2)
        .await
        .expect("a page");
    assert_eq!(names(next), ["charlie", "delta"]);
    let last = storage
        .companies
        .page(Some(&id("delta")), 2)
        .await
        .expect("a page");
    assert!(last.is_empty());
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn only_active_companies_are_served() {
    let storage = directory().await;
    for raw in ["alpha", "bravo", "charlie", "delta"] {
        storage
            .companies
            .create(&id(raw), raw, "user-1", Timestamp::from_unix_secs(AT))
            .await
            .expect("created");
    }
    for raw in ["alpha", "bravo", "delta"] {
        assert!(
            storage
                .companies
                .transition(&id(raw), CompanyStatus::Provisioning, CompanyStatus::Active)
                .await
                .expect("activated")
        );
    }
    assert!(
        storage
            .companies
            .transition(
                &id("bravo"),
                CompanyStatus::Active,
                CompanyStatus::Suspended
            )
            .await
            .expect("suspended")
    );
    let mut active = storage
        .companies
        .active()
        .await
        .expect("the active companies");
    active.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(active, [id("alpha"), id("delta")]);
}
