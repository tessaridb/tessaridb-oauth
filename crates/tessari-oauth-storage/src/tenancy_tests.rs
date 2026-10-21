use tessari_oauth_infrastructure::Error as StoreError;
use tessari_oauth_types::TenantId;

use super::Tenancy;
use crate::Error;

fn tenant(raw: &str) -> TenantId {
    TenantId::parse(raw).expect("fixture tenant")
}

#[test]
fn a_tenant_lives_in_its_regions_namespace_and_its_own_database() {
    let place = Tenancy::for_region("eu")
        .expect("plain region")
        .place(&tenant("acme-corp"))
        .expect("place");
    assert_eq!(place.namespace(), "oauth_eu");
    assert_eq!(place.database(), "t_acme_corp");
}

#[test]
fn distinct_tenants_never_share_a_database() {
    let tenancy = Tenancy::for_region("eu").expect("plain region");
    let first = tenancy.place(&tenant("a-b")).expect("place");
    let second = tenancy.place(&tenant("ab")).expect("place");
    assert_ne!(first.database(), second.database());
}

#[test]
fn a_region_that_is_not_a_plain_name_is_refused() {
    for region in ["eu-west", "eu; DROP"] {
        let refused = Tenancy::for_region(region);
        assert!(
            matches!(refused, Err(Error::Store(StoreError::InvalidName { .. }))),
            "{region}: {refused:?}"
        );
    }
}
