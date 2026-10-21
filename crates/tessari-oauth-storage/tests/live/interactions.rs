//! A pending authorization is kept exactly as it was validated, under an id nobody can guess, for its ten minutes —
//! and only in the tenant it was made to. A pushed one (RFC 9126) waits unclaimed for its minute, and only the client
//! that pushed it can claim it, once.

use std::collections::BTreeSet;

use tessari_oauth_constants::{INTERACTION_TTL_SECS, PUSHED_REQUEST_TTL_SECS};
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_types::{Challenge, ClientId, Resource, ScopeSet, TenantId, Timestamp};

use crate::fresh;

const START: u64 = 1_800_000_000;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn at(offset: u64) -> Timestamp {
    Timestamp::from_unix_secs(START.checked_add(offset).expect("a time within range"))
}

fn request(state: Option<&str>, nonce: Option<&str>) -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: ClientId::parse("portal").expect("a client id"),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scopes: ScopeSet::parse("openid api:read").expect("scopes"),
        challenge: Challenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .expect("a challenge"),
        state: state.map(str::to_owned),
        resources: BTreeSet::from([
            Resource::parse("https://api.example.com/").expect("a resource")
        ]),
        nonce: nonce.map(str::to_owned),
        silent: false,
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_pending_authorization_reads_back_as_it_was_kept_until_it_lapses() {
    let storage = fresh(&tenant("acme"), 2).await;
    let interactions = &storage.interactions;
    let full = request(Some("af0ifjsldkj"), Some("n-0S6_WzA2Mj"));
    let bare = request(None, None);
    let first = interactions
        .open(&tenant("acme"), &full, at(0))
        .await
        .expect("kept");
    let second = interactions
        .open(&tenant("acme"), &bare, at(0))
        .await
        .expect("kept");
    assert_ne!(first, second, "each is kept under its own id");
    assert!(
        first.len() >= 22,
        "an id of at least 128 random bits: {first}"
    );

    let last_moment = INTERACTION_TTL_SECS
        .checked_sub(1)
        .expect("a positive lifetime");
    assert_eq!(
        interactions
            .find(&tenant("acme"), &first, at(last_moment))
            .await
            .expect("read"),
        Some(full)
    );
    assert_eq!(
        interactions
            .find(&tenant("acme"), &second, at(0))
            .await
            .expect("read"),
        Some(bare)
    );
    assert_eq!(
        interactions
            .find(&tenant("acme"), &first, at(INTERACTION_TTL_SECS))
            .await
            .expect("read"),
        None,
        "lapsed at its lifetime"
    );
    assert_eq!(
        interactions
            .find(&tenant("acme"), "never-opened", at(0))
            .await
            .expect("read"),
        None
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_pending_authorization_is_not_found_from_another_tenant() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("initech"))
        .await
        .expect("provisioned");
    let id = storage
        .interactions
        .open(&tenant("acme"), &request(None, None), at(0))
        .await
        .expect("kept");
    assert_eq!(
        storage
            .interactions
            .find(&tenant("initech"), &id, at(1))
            .await
            .expect("read"),
        None
    );
}

fn portal() -> ClientId {
    ClientId::parse("portal").expect("a client id")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_pushed_request_is_claimed_once_by_its_client_then_read_as_pending() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("initech"))
        .await
        .expect("provisioned");
    let interactions = &storage.interactions;
    let pushed = request(Some("af0ifjsldkj"), None);
    let id = interactions
        .push(&tenant("acme"), &pushed, at(0))
        .await
        .expect("kept");
    assert_eq!(
        interactions
            .find(&tenant("acme"), &id, at(1))
            .await
            .expect("read"),
        None,
        "not a pending sign-in until the browser brings it"
    );
    let kiosk = ClientId::parse("kiosk").expect("a client id");
    assert_eq!(
        interactions
            .claim(&tenant("acme"), &id, &kiosk, at(1))
            .await
            .expect("claimed"),
        None,
        "another client cannot claim it"
    );
    assert_eq!(
        interactions
            .claim(&tenant("initech"), &id, &portal(), at(1))
            .await
            .expect("claimed"),
        None,
        "nor another tenant"
    );
    let last_moment = PUSHED_REQUEST_TTL_SECS
        .checked_sub(1)
        .expect("a positive lifetime");
    assert_eq!(
        interactions
            .claim(&tenant("acme"), &id, &portal(), at(last_moment))
            .await
            .expect("claimed"),
        Some(pushed.clone()),
        "its own client claims it within its minute, after the refused attempts"
    );
    assert_eq!(
        interactions
            .claim(&tenant("acme"), &id, &portal(), at(last_moment))
            .await
            .expect("claimed"),
        None,
        "once"
    );
    assert_eq!(
        interactions
            .find(&tenant("acme"), &id, at(last_moment))
            .await
            .expect("read"),
        Some(pushed),
        "claimed, it is a pending sign-in"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_pushed_request_lapses_at_its_minute_and_an_opened_one_cannot_be_claimed() {
    let storage = fresh(&tenant("acme"), 2).await;
    let interactions = &storage.interactions;
    let pushed = interactions
        .push(&tenant("acme"), &request(None, None), at(0))
        .await
        .expect("kept");
    assert_eq!(
        interactions
            .claim(
                &tenant("acme"),
                &pushed,
                &portal(),
                at(PUSHED_REQUEST_TTL_SECS)
            )
            .await
            .expect("claimed"),
        None,
        "lapsed at its lifetime"
    );
    let opened = interactions
        .open(&tenant("acme"), &request(None, None), at(0))
        .await
        .expect("kept");
    assert_eq!(
        interactions
            .claim(&tenant("acme"), &opened, &portal(), at(1))
            .await
            .expect("claimed"),
        None,
        "a request the browser brought itself is claimed already"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_silent_request_reads_back_silent() {
    let storage = fresh(&tenant("acme"), 2).await;
    let silent = AuthorizationRequest {
        silent: true,
        ..request(None, None)
    };
    let id = storage
        .interactions
        .push(&tenant("acme"), &silent, at(0))
        .await
        .expect("kept");
    assert_eq!(
        storage
            .interactions
            .claim(&tenant("acme"), &id, &portal(), at(1))
            .await
            .expect("claimed"),
        Some(silent)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn of_simultaneous_claims_of_one_pushed_request_exactly_one_succeeds() {
    let storage = std::sync::Arc::new(fresh(&tenant("acme"), 9).await);
    for round in 0..10 {
        let id = storage
            .interactions
            .push(&tenant("acme"), &request(None, None), at(0))
            .await
            .expect("kept");
        let mut racers = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let (storage, id) = (std::sync::Arc::clone(&storage), id.clone());
            racers.spawn(async move {
                storage
                    .interactions
                    .claim(&tenant("acme"), &id, &portal(), at(1))
                    .await
            });
        }
        let claimed = racers
            .join_all()
            .await
            .into_iter()
            .map(|outcome| outcome.unwrap_or_else(|error| panic!("round {round}: {error:?}")))
            .filter(Option::is_some)
            .count();
        assert_eq!(claimed, 1, "round {round}");
    }
}
