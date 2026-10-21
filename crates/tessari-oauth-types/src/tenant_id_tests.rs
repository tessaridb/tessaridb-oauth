use tessari_oauth_constants::TENANT_ID_MAX_LEN;

use super::TenantId;
use crate::Error;

#[test]
fn ids_inside_the_grammar_are_accepted_as_written() {
    for raw in [
        "acme",
        "a",
        "tenant-42",
        "0",
        &"a".repeat(TENANT_ID_MAX_LEN),
    ] {
        assert_eq!(
            TenantId::parse(raw).map(|id| id.as_str().to_owned()),
            Ok(raw.to_owned())
        );
    }
}

#[test]
fn ids_outside_the_grammar_are_refused() {
    for raw in [
        String::new(),
        "a".repeat(TENANT_ID_MAX_LEN + 1),
        "Acme".to_owned(),
        "-acme".to_owned(),
        "acme-".to_owned(),
        "ac_me".to_owned(),
        "ac.me".to_owned(),
        "ac/me".to_owned(),
        "acmé".to_owned(),
    ] {
        assert!(
            matches!(
                TenantId::parse(raw.clone()),
                Err(Error::Invalid {
                    field: "tenant",
                    ..
                })
            ),
            "{raw:?} should be refused"
        );
    }
}
