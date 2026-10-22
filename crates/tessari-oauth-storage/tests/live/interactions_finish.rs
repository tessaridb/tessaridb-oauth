//! A pending authorization is taken once, when the code it was waiting for is issued: the taker gets it as it was
//! kept, every later or simultaneous taker gets nothing, and a lapsed one, a pushed one nobody brought, or one from
//! another tenant is never handed out.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_constants::INTERACTION_TTL_SECS;
use tessari_oauth_core::authorize::AuthorizationRequest;
use tessari_oauth_types::{
    BrowserBinding, Challenge, ClientId, Resource, ScopeSet, TenantId, Timestamp,
};
use tokio::sync::Barrier;

use crate::fresh;

const START: u64 = 1_800_000_000;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn at(offset: u64) -> Timestamp {
    Timestamp::from_unix_secs(START.checked_add(offset).expect("a time within range"))
}

/// The browser that brought the request.
fn browser() -> BrowserBinding {
    BrowserBinding::from_secret("browser-a")
}

fn request() -> AuthorizationRequest {
    AuthorizationRequest {
        client_id: ClientId::parse("portal").expect("a client id"),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scopes: ScopeSet::parse("openid api:read").expect("scopes"),
        challenge: Challenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
            .expect("a challenge"),
        state: Some("af0ifjsldkj".to_owned()),
        resources: BTreeSet::from([
            Resource::parse("https://api.example.com/").expect("a resource")
        ]),
        nonce: Some("n-0S6_WzA2Mj".to_owned()),
        silent: false,
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_pending_authorization_is_taken_once_as_it_was_kept() {
    let storage = fresh(&tenant("acme"), 2).await;
    let interactions = &storage.interactions;
    let id = interactions
        .open(&tenant("acme"), &request(), &browser(), at(0))
        .await
        .expect("kept");
    let taken = interactions
        .finish(&tenant("acme"), &id, &browser(), at(1))
        .await
        .expect("the store answers");
    assert_eq!(taken, Some(request()));
    for case in ["taken again", "found after"] {
        let again = if case == "taken again" {
            interactions
                .finish(&tenant("acme"), &id, &browser(), at(2))
                .await
        } else {
            interactions
                .find(&tenant("acme"), &id, &browser(), at(2))
                .await
        };
        assert_eq!(again.expect("the store answers"), None, "{case}");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_lapsed_unbrought_or_foreign_authorization_is_never_handed_out() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("initech"))
        .await
        .expect("provisioned");
    let interactions = &storage.interactions;
    let lapsed = interactions
        .open(&tenant("acme"), &request(), &browser(), at(0))
        .await
        .expect("kept");
    let pushed = interactions
        .push(&tenant("acme"), &request(), at(0))
        .await
        .expect("kept");
    let foreign = interactions
        .open(&tenant("acme"), &request(), &browser(), at(0))
        .await
        .expect("kept");
    for (tenant_name, id, when, case) in [
        ("acme", lapsed.as_str(), INTERACTION_TTL_SECS, "lapsed"),
        ("acme", pushed.as_str(), 1, "pushed, never brought"),
        ("initech", foreign.as_str(), 1, "another tenant's"),
        ("acme", "never-opened", 1, "never opened"),
    ] {
        let taken = interactions
            .finish(&tenant(tenant_name), id, &browser(), at(when))
            .await
            .expect("the store answers");
        assert_eq!(taken, None, "{case}");
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn sixteen_simultaneous_takers_of_one_authorization_get_it_once() {
    let storage = fresh(&tenant("acme"), 16).await;
    for round in 0..5_u64 {
        let id = storage
            .interactions
            .open(&tenant("acme"), &request(), &browser(), at(0))
            .await
            .expect("kept");
        let start = Arc::new(Barrier::new(16));
        let racers: Vec<_> = (0..16)
            .map(|_| {
                let (storage, start, id) = (storage.clone(), Arc::clone(&start), id.clone());
                tokio::spawn(async move {
                    start.wait().await;
                    storage
                        .interactions
                        .finish(&tenant("acme"), &id, &browser(), at(1))
                        .await
                })
            })
            .collect();
        let mut answers = Vec::new();
        for racer in racers {
            answers.push(racer.await.expect("the task finished"));
        }
        let taken = answers
            .iter()
            .filter(|answer| matches!(answer, Ok(Some(_))))
            .count();
        assert_eq!(taken, 1, "round {round}: {answers:?}");
        assert!(
            answers.iter().all(Result::is_ok),
            "round {round}: no taker failed: {answers:?}"
        );
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn another_browser_finds_takes_and_spoils_nothing() {
    let storage = fresh(&tenant("acme"), 2).await;
    let interactions = &storage.interactions;
    let other = BrowserBinding::from_secret("browser-b");
    let opened = interactions
        .open(&tenant("acme"), &request(), &browser(), at(0))
        .await
        .expect("kept");
    let pushed = interactions
        .push(&tenant("acme"), &request(), at(0))
        .await
        .expect("kept");
    let claimed = interactions
        .claim(
            &tenant("acme"),
            &pushed,
            &request().client_id,
            &browser(),
            at(1),
        )
        .await
        .expect("the store answers");
    assert_eq!(claimed, Some(request()), "the pushed request is brought");
    for (id, case) in [(&opened, "opened"), (&pushed, "pushed then claimed")] {
        let found = interactions
            .find(&tenant("acme"), id, &other, at(2))
            .await
            .expect("the store answers");
        assert_eq!(found, None, "{case}: found from another browser");
        let taken = interactions
            .finish(&tenant("acme"), id, &other, at(2))
            .await
            .expect("the store answers");
        assert_eq!(taken, None, "{case}: taken from another browser");
        let taken = interactions
            .finish(&tenant("acme"), id, &browser(), at(3))
            .await
            .expect("the store answers");
        assert_eq!(
            taken,
            Some(request()),
            "{case}: still there for its own browser"
        );
    }
}
