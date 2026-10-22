use tessari_oauth_types::TenantId;

use super::Served;

fn id(raw: &str) -> TenantId {
    TenantId::parse(raw).expect("a tenant id")
}

#[test]
fn a_served_company_has_its_issuer_under_the_base() {
    let served = Served::new("https://id.example.com/");
    served.replace([id("acme"), id("initech")]);
    assert_eq!(
        served.issuer(&id("acme")).as_deref(),
        Some("https://id.example.com/acme")
    );
    assert_eq!(served.issuer(&id("globex")), None);
    let mut companies = served.companies();
    companies.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(companies, [id("acme"), id("initech")]);
}

#[test]
fn a_replacement_drops_the_companies_it_does_not_name() {
    let served = Served::new("https://id.example.com");
    served.replace([id("acme"), id("initech")]);
    served.replace([id("initech")]);
    assert_eq!(served.issuer(&id("acme")), None);
    assert!(served.issuer(&id("initech")).is_some());
}
