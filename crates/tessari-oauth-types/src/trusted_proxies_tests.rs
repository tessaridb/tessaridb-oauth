use std::net::IpAddr;

use super::TrustedProxies;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

#[test]
fn an_address_trusts_itself_and_a_network_every_address_inside_it() {
    let proxies = TrustedProxies::parse("10.0.0.5, 172.16.0.0/12 ,fd00::/8").expect("a list");
    assert!(proxies.contains(ip("10.0.0.5")));
    assert!(
        !proxies.contains(ip("10.0.0.6")),
        "an address is not its neighbours"
    );
    assert!(proxies.contains(ip("172.31.255.255")));
    assert!(
        !proxies.contains(ip("172.32.0.0")),
        "just outside the network"
    );
    assert!(proxies.contains(ip("fd12::1")));
    assert!(!proxies.contains(ip("fe80::1")));
    assert!(
        proxies.contains(ip("::ffff:10.0.0.5")),
        "an IPv4-mapped peer is its IPv4 address"
    );
}

#[test]
fn an_empty_list_trusts_nobody() {
    let proxies = TrustedProxies::parse("").expect("an empty list");
    assert!(proxies.is_empty());
    assert!(!proxies.contains(ip("127.0.0.1")));
    assert!(TrustedProxies::default().is_empty());
}

#[test]
fn an_entry_that_is_not_an_address_or_network_refuses_the_list() {
    for bad in [
        "localhost",
        "10.0.0.0/33",
        "fd00::/129",
        "10.0.0.1/",
        "/8",
        "10.0.0.0/8,,",
        "10.0.0.0/-1",
    ] {
        let refused = TrustedProxies::parse(bad);
        assert!(
            matches!(
                &refused,
                Err(crate::Error::Invalid {
                    field: "trusted_proxies",
                    ..
                })
            ),
            "{bad}: {refused:?}"
        );
    }
}

#[test]
fn a_network_is_kept_by_its_prefix_whatever_host_bits_are_written() {
    let proxies = TrustedProxies::parse("192.168.7.9/16").expect("a list");
    assert!(proxies.contains(ip("192.168.200.1")));
    assert!(!proxies.contains(ip("192.169.0.1")));
}
