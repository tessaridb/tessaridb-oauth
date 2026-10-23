use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use tessari_oauth_types::TrustedProxies;

use super::client;

/// A request from `peer` carrying `forwarded` as its `X-Forwarded-For` headers, behind `proxies` when given.
fn request(peer: &str, forwarded: &[&str], proxies: Option<&str>) -> Request {
    let mut builder = Request::builder().uri("/acme/login");
    for value in forwarded {
        builder = builder.header("x-forwarded-for", *value);
    }
    let mut request = builder.body(Body::empty()).expect("a request");
    let peer: SocketAddr = peer.parse().expect("a socket address");
    request.extensions_mut().insert(ConnectInfo(peer));
    if let Some(proxies) = proxies {
        let proxies = TrustedProxies::parse(proxies).expect("a list");
        request.extensions_mut().insert(Arc::new(proxies));
    }
    request
}

#[test]
fn a_forwarded_header_from_a_peer_nobody_trusts_is_ignored() {
    let forged = request("198.51.100.7:4000", &["203.0.113.9"], None);
    assert_eq!(client(&forged), "198.51.100.7", "no proxy trusted");
    let untrusted = request("198.51.100.7:4000", &["203.0.113.9"], Some("10.0.0.0/8"));
    assert_eq!(
        client(&untrusted),
        "198.51.100.7",
        "a peer outside the list"
    );
}

#[test]
fn behind_a_trusted_proxy_the_client_is_the_right_most_address_it_did_not_add_itself() {
    // The client wrote the first entry; nginx appended what it saw; a second trusted hop appended the first.
    let chain = request(
        "10.0.0.2:5000",
        &["6.6.6.6, 203.0.113.9", "10.0.0.1"],
        Some("10.0.0.0/8"),
    );
    assert_eq!(client(&chain), "203.0.113.9");
    let one = request("10.0.0.2:5000", &["203.0.113.9"], Some("10.0.0.2"));
    assert_eq!(client(&one), "203.0.113.9");
    let v6 = request(
        "[fd00::2]:5000",
        &["2001:db8:1:2:3:4:5:6"],
        Some("fd00::/8"),
    );
    assert_eq!(
        client(&v6),
        "2001:db8:1:2::/64",
        "an IPv6 client still by its /64"
    );
}

#[test]
fn a_trusted_proxy_that_names_nobody_is_counted_as_itself() {
    let silent = request("10.0.0.2:5000", &[], Some("10.0.0.0/8"));
    assert_eq!(client(&silent), "10.0.0.2");
    let garbage = request("10.0.0.2:5000", &["not-an-address"], Some("10.0.0.0/8"));
    assert_eq!(
        client(&garbage),
        "10.0.0.2",
        "an entry that does not read stops the walk"
    );
    let behind = request("10.0.0.2:5000", &["203.0.113.9, junk"], Some("10.0.0.0/8"));
    assert_eq!(
        client(&behind),
        "10.0.0.2",
        "nothing left of an unreadable hop is believed"
    );
}
