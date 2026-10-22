//! Sign-ins in progress: found only by the browser that began them, moved on one step at a time from the revision
//! they were read at (of eight browsers' worth of simultaneous steps from one place exactly one is kept), finished
//! once, and gone after an authorization request's lifetime.

use std::sync::Arc;

use tessari_oauth_constants::INTERACTION_TTL_SECS;
use tessari_oauth_core::authentication::Method;
use tessari_oauth_core::ceremony::{Ceremony, Identity, Stage};
use tessari_oauth_storage::Storage;
use tessari_oauth_types::{SigninBinding, TenantId, Timestamp, UserId};
use tokio::sync::Barrier;

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);
const RACERS: usize = 8;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn binding(value: &str) -> SigninBinding {
    SigninBinding::from_secret(value)
}

fn identified() -> Ceremony {
    Ceremony::new()
        .identify(Identity::Known {
            user: UserId::parse("user-1").expect("a user id"),
            second_factor: true,
        })
        .expect("identified")
}

async fn begun(storage: &Storage) {
    assert_eq!(
        storage
            .signins
            .begin(&tenant("acme"), &binding("browser-1"), "interaction-1", NOW)
            .await,
        Ok(true)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_sign_in_is_found_by_its_browser_moved_on_from_where_it_was_read_and_finished_once() {
    let storage = fresh(&tenant("acme"), 2).await;
    begun(&storage).await;
    let signins = &storage.signins;
    let acme = tenant("acme");
    assert_eq!(
        signins
            .begin(&acme, &binding("browser-1"), "interaction-2", NOW)
            .await,
        Ok(false),
        "one sign-in per browser"
    );
    assert_eq!(
        signins.resume(&acme, &binding("browser-2"), NOW).await,
        Ok(None),
        "another browser finds nothing"
    );
    let started = signins
        .resume(&acme, &binding("browser-1"), NOW)
        .await
        .expect("read")
        .expect("a sign-in");
    assert_eq!(started.interaction, "interaction-1");
    assert_eq!(started.ceremony.stage(), Stage::Identify);
    let step = identified();
    assert_eq!(
        signins
            .advance(
                &acme,
                &binding("browser-1"),
                started.revision,
                &step,
                Some("key-1")
            )
            .await,
        Ok(true)
    );
    assert_eq!(
        signins
            .advance(
                &acme,
                &binding("browser-1"),
                started.revision,
                &step,
                Some("key-1")
            )
            .await,
        Ok(false),
        "a step from a place already left"
    );
    let moved = signins
        .resume(&acme, &binding("browser-1"), NOW)
        .await
        .expect("read")
        .expect("a sign-in");
    assert_eq!(moved.ceremony, step);
    assert_eq!(
        moved.account.as_deref(),
        Some("key-1"),
        "counted under the identified key"
    );
    assert_ne!(moved.revision, started.revision);
    let second = step.verified(Method::Password).expect("first factor");
    assert_eq!(
        signins
            .advance(
                &acme,
                &binding("browser-1"),
                moved.revision,
                &second,
                moved.account.as_deref()
            )
            .await,
        Ok(true)
    );
    let finished = signins
        .finish(&acme, &binding("browser-1"), NOW)
        .await
        .expect("finished")
        .expect("a sign-in");
    assert_eq!(finished.ceremony, second, "the methods are kept in order");
    assert_eq!(finished.account.as_deref(), Some("key-1"));
    assert_eq!(finished.interaction, "interaction-1");
    assert_eq!(
        signins.finish(&acme, &binding("browser-1"), NOW).await,
        Ok(None),
        "once"
    );
    assert_eq!(
        signins.resume(&acme, &binding("browser-1"), NOW).await,
        Ok(None)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn of_simultaneous_steps_from_one_place_exactly_one_is_kept() {
    let storage = Arc::new(fresh(&tenant("acme"), RACERS).await);
    begun(&storage).await;
    let start = storage
        .signins
        .resume(&tenant("acme"), &binding("browser-1"), NOW)
        .await
        .expect("read")
        .expect("a sign-in")
        .revision;
    let barrier = Arc::new(Barrier::new(RACERS));
    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..RACERS {
        let (storage, barrier) = (Arc::clone(&storage), Arc::clone(&barrier));
        racers.spawn(async move {
            barrier.wait().await;
            storage
                .signins
                .advance(
                    &tenant("acme"),
                    &binding("browser-1"),
                    start,
                    &identified(),
                    None,
                )
                .await
        });
    }
    let mut kept = 0_usize;
    while let Some(outcome) = racers.join_next().await {
        if outcome.expect("joined").expect("answered") {
            kept = kept.saturating_add(1);
        }
    }
    assert_eq!(kept, 1);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_sign_in_ends_with_its_request_and_stays_in_its_tenant() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    begun(&storage).await;
    let lapsed = Timestamp::from_unix_secs(
        1_800_000_000_u64
            .checked_add(INTERACTION_TTL_SECS)
            .expect("an instant"),
    );
    let signins = &storage.signins;
    assert_eq!(
        signins
            .resume(&tenant("acme"), &binding("browser-1"), lapsed)
            .await,
        Ok(None)
    );
    assert_eq!(
        signins
            .finish(&tenant("acme"), &binding("browser-1"), lapsed)
            .await,
        Ok(None)
    );
    assert_eq!(
        signins
            .resume(&tenant("globex"), &binding("browser-1"), NOW)
            .await,
        Ok(None),
        "another tenant"
    );
}
