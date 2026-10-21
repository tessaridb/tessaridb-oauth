//! A pending authorization is kept exactly as it was validated, under an id nobody can guess, for its ten minutes —
//! and only in the tenant it was made to.

use std::collections::BTreeSet;

use tessari_oauth_constants::INTERACTION_TTL_SECS;
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
