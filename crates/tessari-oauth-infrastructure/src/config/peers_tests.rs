use super::{PeerRegion, PeerVariables, peer_settings};
use crate::Error;

fn variables(list: Option<&str>) -> PeerVariables {
    PeerVariables {
        list: list.map(str::to_owned),
        user: Some("peer".to_owned()),
        password: Some("peer-s3cret".to_owned()),
        authority: Some("/run/tls/peers.pem".to_owned()),
    }
}

fn region(region: &str, address: &str) -> PeerRegion {
    PeerRegion {
        region: region.to_owned(),
        address: address.to_owned(),
    }
}

#[test]
fn no_list_means_no_peer_and_needs_no_account() {
    let unset = PeerVariables {
        list: None,
        user: None,
        password: None,
        authority: None,
    };
    assert_eq!(peer_settings(unset, "eu"), Ok(None));
}

#[test]
fn a_list_names_each_region_and_its_store_in_order() {
    let settings = peer_settings(
        variables(Some("us=db.us.example.com:7000, ap=10.0.0.9:7000")),
        "eu",
    )
    .expect("valid")
    .expect("peers");
    assert_eq!(
        settings.regions,
        vec![
            region("us", "db.us.example.com:7000"),
            region("ap", "10.0.0.9:7000")
        ]
    );
    assert_eq!(settings.user, "peer");
    assert_eq!(
        settings.authority.as_deref().and_then(|path| path.to_str()),
        Some("/run/tls/peers.pem")
    );
    assert!(
        !format!("{settings:?}").contains("peer-s3cret"),
        "the password is never printed"
    );
}

#[test]
fn a_list_without_its_account_is_refused_naming_the_variable() {
    let mut without_user = variables(Some("us=db.us.example.com:7000"));
    without_user.user = None;
    assert_eq!(
        peer_settings(without_user, "eu"),
        Err(Error::Unset {
            key: "TESSARIDB_OAUTH_PEER_USER"
        })
    );
    let mut without_password = variables(Some("us=db.us.example.com:7000"));
    without_password.password = None;
    assert_eq!(
        peer_settings(without_password, "eu"),
        Err(Error::Unset {
            key: "TESSARIDB_OAUTH_PEER_PASSWORD"
        })
    );
}

#[test]
fn a_malformed_repeated_or_own_region_is_refused() {
    for list in [
        "us",
        "=db.us.example.com:7000",
        "us=",
        "us=db.us.example.com",
        "us=https://db.us.example.com:7000",
        "us=db.us.example.com:7000,us=db2.us.example.com:7000",
        "eu=db.eu.example.com:7000",
    ] {
        assert!(
            matches!(
                peer_settings(variables(Some(list)), "eu"),
                Err(Error::Invalid {
                    key: "TESSARIDB_OAUTH_PEERS",
                    ..
                })
            ),
            "{list}"
        );
    }
}
