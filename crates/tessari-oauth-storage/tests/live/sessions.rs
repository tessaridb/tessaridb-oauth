//! Sessions at this issuer: found only by their own cookie and only in their tenant, saying what the sign-in
//! established, kept alive by the requests that find them up to a week, gone after a working day without one, and
//! ended once.

use tessari_oauth_constants::{SESSION_ABSOLUTE_SECS, SESSION_IDLE_SECS};
use tessari_oauth_core::authentication::{Method, assess};
use tessari_oauth_storage::Storage;
use tessari_oauth_types::{SessionSecret, TenantId, Timestamp, UserId};

use crate::fresh;

const START: u64 = 1_800_000_000;
const METHODS: [Method; 2] = [Method::Password, Method::Totp];

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn secret(value: &str) -> SessionSecret {
    SessionSecret::from_secret(value)
}

fn at(offset: u64) -> Timestamp {
    Timestamp::from_unix_secs(START.checked_add(offset).expect("an instant"))
}

async fn opened(storage: &Storage) {
    assert_eq!(
        storage
            .sessions
            .create(
                &tenant("acme"),
                &secret("cookie-1"),
                &UserId::parse("user-1").expect("a user id"),
                &METHODS,
                at(0)
            )
            .await,
        Ok(())
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_session_is_found_by_its_cookie_says_what_the_sign_in_established_and_ends_once() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    opened(&storage).await;
    let sessions = &storage.sessions;
    let found = sessions
        .find(&tenant("acme"), &secret("cookie-1"), at(1))
        .await
        .expect("read")
        .expect("a session");
    assert_eq!(found.user, UserId::parse("user-1").expect("a user id"));
    assert_eq!(found.auth_time, at(0));
    assert_eq!(Some(found.assessment), assess(&METHODS));
    assert_eq!(
        sessions
            .find(&tenant("acme"), &secret("cookie-2"), at(1))
            .await,
        Ok(None)
    );
    assert_eq!(
        sessions
            .find(&tenant("globex"), &secret("cookie-1"), at(1))
            .await,
        Ok(None)
    );
    assert_eq!(
        sessions.end(&tenant("acme"), &secret("cookie-1")).await,
        Ok(true)
    );
    assert_eq!(
        sessions.end(&tenant("acme"), &secret("cookie-1")).await,
        Ok(false),
        "once"
    );
    assert_eq!(
        sessions
            .find(&tenant("acme"), &secret("cookie-1"), at(2))
            .await,
        Ok(None)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_session_lapses_after_a_working_day_unseen_and_a_week_in_all() {
    let storage = fresh(&tenant("acme"), 2).await;
    opened(&storage).await;
    let sessions = &storage.sessions;
    let (acme, cookie) = (tenant("acme"), secret("cookie-1"));
    let step = SESSION_IDLE_SECS.checked_sub(1).expect("a step");
    let mut offset = 0_u64;
    // Found once inside every idle window, it stays alive until its week is up.
    while offset.checked_add(step).expect("an offset") < SESSION_ABSOLUTE_SECS {
        offset = offset.checked_add(step).expect("an offset");
        assert!(
            sessions
                .find(&acme, &cookie, at(offset))
                .await
                .expect("read")
                .is_some(),
            "alive at {offset}"
        );
    }
    assert_eq!(
        sessions
            .find(&acme, &cookie, at(SESSION_ABSOLUTE_SECS))
            .await,
        Ok(None),
        "a week in all"
    );

    let idle = fresh(&tenant("acme"), 2).await;
    opened(&idle).await;
    assert_eq!(
        idle.sessions
            .find(&acme, &cookie, at(SESSION_IDLE_SECS))
            .await,
        Ok(None),
        "a working day unseen"
    );
}
