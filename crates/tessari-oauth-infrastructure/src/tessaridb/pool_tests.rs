use super::Database;
use crate::Error;
use crate::tessaridb::StoreConfig;

/// A test authority's certificate; public material only.
const AUTHORITY: &[u8] = include_bytes!("pool_tests_authority.pem");

fn config(address: &str, authority: Option<&[u8]>) -> StoreConfig {
    StoreConfig {
        address: address.to_owned(),
        user: "oauth".to_owned(),
        password: "not used".to_owned(),
        authority: authority.map(<[u8]>::to_vec),
    }
}

#[test]
fn the_clear_is_accepted_only_to_a_loopback_ip_literal() {
    for address in ["127.0.0.1:9080", "[::1]:9080"] {
        assert!(Database::new(config(address, None), 1).is_ok(), "{address}");
    }
}

#[test]
fn the_clear_to_any_other_address_is_refused_at_construction() {
    for address in [
        "10.0.0.5:9080",
        "store.internal:9080",
        "localhost:9080",
        "0.0.0.0:9080",
        "garbage",
    ] {
        let refused = Database::new(config(address, None), 1);
        assert!(
            matches!(
                refused,
                Err(Error::InvalidConfig {
                    field: "store_authority",
                    ..
                })
            ),
            "{address}: {:?}",
            refused.err()
        );
    }
}

#[test]
fn an_authority_is_accepted_for_any_address_and_one_that_is_no_certificate_is_refused() {
    assert!(Database::new(config("store.internal:9080", Some(AUTHORITY)), 1).is_ok());
    let refused = Database::new(config("store.internal:9080", Some(b"not a certificate")), 1);
    assert!(
        matches!(
            refused,
            Err(Error::InvalidConfig {
                field: "store_authority",
                ..
            })
        ),
        "{:?}",
        refused.err()
    );
}
