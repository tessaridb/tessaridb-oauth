use std::sync::Arc;

use tessari_oauth_types::TenantId;

use super::Elsewhere;

fn company(id: &str) -> TenantId {
    TenantId::parse(id).expect("a company id")
}

#[test]
fn a_company_another_region_serves_is_found_at_that_regions_base() {
    let elsewhere = Elsewhere::new();
    assert_eq!(elsewhere.home(&company("beta")), None);
    let us: Arc<str> = "https://us.id.example.com".into();
    elsewhere.replace([(company("beta"), Arc::clone(&us))]);
    assert_eq!(elsewhere.home(&company("beta")), Some(us));
    assert_eq!(elsewhere.home(&company("gamma")), None);
}

#[test]
fn a_replacement_forgets_a_company_no_peer_names_any_more() {
    let elsewhere = Elsewhere::new();
    elsewhere.replace([(company("beta"), "https://us.id.example.com".into())]);
    elsewhere.replace([(company("gamma"), "https://ap.id.example.com".into())]);
    assert_eq!(elsewhere.home(&company("beta")), None);
    assert!(elsewhere.home(&company("gamma")).is_some());
}
