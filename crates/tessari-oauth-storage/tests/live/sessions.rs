//! Sessions at this issuer: found only by their own cookie and only in their tenant, saying what the sign-in
//! established, kept alive by the requests that find them up to a week, gone after a working day without one, and
//! ended once.

use tessari_oauth_constants::{SESSION_ABSOLUTE_SECS, SESSION_IDLE_SECS};
use tessari_oauth_core::authentication::{Method, assess};
use tessari_oauth_storage::Storage;
use tessari_oauth_types::{ClientId, SessionSecret, TenantId, Timestamp, UserId};

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

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_session_has_a_public_id_of_its_own_that_names_no_cookie() {
    let storage = fresh(&tenant("acme"), 2).await;
    opened(&storage).await;
    storage
        .sessions
        .create(
            &tenant("acme"),
            &secret("cookie-2"),
            &UserId::parse("user-1").expect("a user id"),
            &METHODS,
            at(0),
        )
        .await
        .expect("opened");
    let find = |value: &'static str, offset: u64| {
        let sessions = storage.sessions.clone();
        async move {
            sessions
                .find(&tenant("acme"), &secret(value), at(offset))
                .await
                .expect("read")
                .expect("a session")
                .sid
        }
    };
    let first = find("cookie-1", 1).await;
    assert_eq!(find("cookie-1", 2).await, first, "stable for the session");
    assert_ne!(find("cookie-2", 1).await, first, "one per session");
    assert!(first.len() >= 22, "at least 128 bits: {first}");
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
    assert_ne!(first, "cookie-1");
    assert_ne!(first, secret("cookie-1").digest(), "not the record's id");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_session_keeps_each_client_it_signed_in_once_even_when_two_record_at_once() {
    let storage = fresh(&tenant("acme"), 4).await;
    opened(&storage).await;
    let acme = tenant("acme");
    let user = UserId::parse("user-1").expect("a user id");
    let found = storage
        .sessions
        .find(&acme, &secret("cookie-1"), at(1))
        .await
        .expect("answered")
        .expect("a live session");
    let portal = ClientId::parse("portal").expect("a client id");
    let kiosk = ClientId::parse("kiosk").expect("a client id");
    let (first, second) = tokio::join!(
        storage
            .sessions
            .record_client(&acme, &user, &found.sid, &portal),
        storage
            .sessions
            .record_client(&acme, &user, &found.sid, &kiosk),
    );
    assert_eq!((first, second), (Ok(true), Ok(true)));
    assert_eq!(
        storage
            .sessions
            .record_client(&acme, &user, &found.sid, &portal)
            .await,
        Ok(true)
    );
    let held = storage
        .sessions
        .find(&acme, &secret("cookie-1"), at(2))
        .await
        .expect("answered")
        .expect("a live session");
    let mut clients = held.clients.clone();
    clients.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(clients, vec![kiosk, portal], "each once, neither lost");
    assert_eq!(
        storage
            .sessions
            .record_client(&acme, &user, "no-such-session", &held.clients[0])
            .await,
        Ok(false)
    );
}
