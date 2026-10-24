use super::{RegistrationPolicy, RegistrationRefused};

fn domains(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn a_company_is_closed_to_registration_until_it_opens() {
    let closed = RegistrationPolicy::default();
    assert!(!closed.is_open());
    assert!(!closed.admits("ada@example.com"));
}

#[test]
fn an_open_company_with_no_domains_admits_any_address() {
    let open = RegistrationPolicy::new(true, Vec::new()).expect("valid");
    assert!(open.admits("ada@example.com"));
    assert!(open.admits("bob@elsewhere.org"));
}

#[test]
fn an_open_company_with_domains_admits_only_those_domains_exactly() {
    let open = RegistrationPolicy::new(true, domains(&["Example.com", "acme.io"])).expect("valid");
    assert_eq!(
        open.domains(),
        ["example.com", "acme.io"],
        "kept lower-case"
    );
    assert!(open.admits("ada@example.com"));
    assert!(
        open.admits("ada@EXAMPLE.COM"),
        "a domain compares without case"
    );
    assert!(open.admits("bob@acme.io"));
    assert!(
        !open.admits("ada@mail.example.com"),
        "a subdomain is another domain"
    );
    assert!(!open.admits("ada@example.com.evil.io"));
    assert!(!open.admits("ada@elsewhere.org"));
    assert!(
        !open.admits("no-at-sign"),
        "an address with no domain is admitted by none"
    );
}

#[test]
fn a_closed_company_keeps_its_domains_and_admits_nobody() {
    let closed = RegistrationPolicy::new(false, domains(&["example.com"])).expect("valid");
    assert_eq!(closed.domains(), ["example.com"]);
    assert!(!closed.admits("ada@example.com"));
}

#[test]
fn a_domain_list_is_refused_when_a_name_is_not_a_domain() {
    for bad in [
        "",
        "localhost",
        "-example.com",
        "example-.com",
        "exa mple.com",
        "example..com",
        "@example.com",
        "*.example.com",
    ] {
        assert_eq!(
            RegistrationPolicy::new(true, domains(&[bad])),
            Err(RegistrationRefused::NotADomain),
            "{bad:?}"
        );
    }
    let long_label = format!("{}.com", "a".repeat(64));
    assert_eq!(
        RegistrationPolicy::new(true, vec![long_label]),
        Err(RegistrationRefused::NotADomain)
    );
}

#[test]
fn a_domain_list_is_refused_with_a_repeat_or_more_than_twenty() {
    assert_eq!(
        RegistrationPolicy::new(true, domains(&["example.com", "EXAMPLE.com"])),
        Err(RegistrationRefused::Repeated)
    );
    let twenty: Vec<String> = (0..20).map(|n| format!("d{n}.example.com")).collect();
    assert!(RegistrationPolicy::new(true, twenty.clone()).is_ok());
    let mut twenty_one = twenty;
    twenty_one.push("d20.example.com".to_owned());
    assert_eq!(
        RegistrationPolicy::new(true, twenty_one),
        Err(RegistrationRefused::TooMany)
    );
}
