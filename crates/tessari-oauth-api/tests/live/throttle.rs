//! Request limits on the public routes: counted per client address in the store, refused past the limit with the
//! time to wait, and refused outright when the store cannot count.

use std::net::SocketAddr;
use std::num::NonZeroU64;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tessari_oauth_api::public_router;
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::throttle::Limit;
use tower::ServiceExt;

use crate::routes::{Answer, answer, header, live_storage, protected, state, unreachable_storage};

const METADATA: &str = "/acme/.well-known/oauth-authorization-server";

fn limit(requests: u64) -> Limit {
    Limit {
        requests: NonZeroU64::new(requests).expect("non-zero"),
        window_secs: NonZeroU64::new(60).expect("non-zero"),
    }
}

/// `GET path` as the listener hands it on: with the peer address `from`, when there is one.
async fn get_from(storage: &Storage, limit: Limit, path: &str, from: Option<&str>) -> Answer {
    let mut request = Request::get(path).body(Body::empty()).expect("a request");
    if let Some(peer) = from {
        let peer: SocketAddr = peer.parse().expect("a socket address");
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    let response = public_router(state(storage, limit))
        .oneshot(request)
        .await
        .expect("the router answers");
    answer(response).await
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_client_past_its_limit_is_refused_with_the_time_to_wait_while_others_are_served() {
    let storage = live_storage().await;
    let from = Some("203.0.113.9:40000");
    for (path, remaining) in [(METADATA, "1"), ("/acme/oauth2/jwks", "0")] {
        let served = get_from(&storage, limit(2), path, from).await;
        assert_ne!(served.status, StatusCode::TOO_MANY_REQUESTS, "{path}");
        assert_eq!(header(&served, "x-ratelimit-limit"), "2", "{path}");
        assert_eq!(
            header(&served, "x-ratelimit-remaining"),
            remaining,
            "{path}"
        );
        assert_eq!(header(&served, "x-ratelimit-class"), "read", "{path}");
    }
    let refused = get_from(&storage, limit(2), METADATA, Some("203.0.113.9:40001")).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.body["code"], "rate_limited");
    // The clock stands at a whole minute, so the whole window is left to wait.
    assert_eq!(header(&refused, "retry-after"), "60");
    assert_eq!(header(&refused, "x-ratelimit-limit"), "2");
    assert_eq!(header(&refused, "x-ratelimit-remaining"), "0");
    assert_eq!(header(&refused, "x-ratelimit-class"), "read");
    protected(&refused);
    let other = get_from(&storage, limit(2), METADATA, Some("198.51.100.7:40000")).await;
    assert_eq!(other.status, StatusCode::OK);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_addresses_of_one_ipv6_64_share_a_count_and_the_next_64_does_not() {
    let storage = live_storage().await;
    let first = get_from(&storage, limit(1), METADATA, Some("[2001:db8:1:2::1]:1")).await;
    assert_eq!(first.status, StatusCode::OK);
    let same = get_from(
        &storage,
        limit(1),
        METADATA,
        Some("[2001:db8:1:2:ffff::9]:2"),
    )
    .await;
    assert_eq!(same.status, StatusCode::TOO_MANY_REQUESTS);
    let next = get_from(&storage, limit(1), METADATA, Some("[2001:db8:1:3::1]:1")).await;
    assert_eq!(next.status, StatusCode::OK);
    let mapped = get_from(&storage, limit(1), METADATA, Some("[::ffff:192.0.2.1]:1")).await;
    assert_eq!(mapped.status, StatusCode::OK);
    let plain = get_from(&storage, limit(1), METADATA, Some("192.0.2.1:1")).await;
    assert_eq!(
        plain.status,
        StatusCode::TOO_MANY_REQUESTS,
        "a mapped address is the IPv4 one"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_request_without_an_address_is_still_counted() {
    let storage = live_storage().await;
    let first = get_from(&storage, limit(1), METADATA, None).await;
    assert_eq!(first.status, StatusCode::OK);
    let second = get_from(&storage, limit(1), METADATA, None).await;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_store_that_cannot_count_refuses_the_request_rather_than_serving_it() {
    let storage = unreachable_storage();
    let answer = get_from(&storage, limit(100), METADATA, Some("203.0.113.9:1")).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.body["code"], "unavailable");
    protected(&answer);
}
