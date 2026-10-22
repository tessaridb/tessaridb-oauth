//! The logouts a tenant owes: ending a session that signed clients in leaves one delivery naming them, whichever way
//! the session ended, in the same commit; a session that signed nobody in leaves nothing; a delivery is held by the
//! claim that took it and finished once.

use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::Storage;
use tessari_oauth_types::{ClientId, SessionSecret, TenantId, Timestamp, UserId};

use crate::fresh;

const START: u64 = 1_800_000_000;

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn user() -> UserId {
    UserId::parse("user-1").expect("a user id")
}

fn client(id: &str) -> ClientId {
    ClientId::parse(id).expect("a client id")
}

/// Open a session under the cookie value `value` that signed in `clients`; its public id.
async fn opened(storage: &Storage, value: &str, clients: &[&str]) -> String {
    let secret = SessionSecret::from_secret(value);
    storage
        .sessions
        .create(
            &acme(),
            &secret,
            &user(),
            &[Method::Password],
            Timestamp::from_unix_secs(START),
        )
        .await
        .expect("opened");
    let sid = storage
        .sessions
        .find(&acme(), &secret, Timestamp::from_unix_secs(START))
        .await
        .expect("answered")
        .expect("a live session")
        .sid;
    for name in clients {
        assert_eq!(
            storage
                .sessions
                .record_client(&acme(), &user(), &sid, &client(name))
                .await,
            Ok(true)
        );
    }
    sid
}

/// The `(sid, clients)` of every delivery a claim now takes, clients sorted.
async fn claimed(storage: &Storage) -> Vec<(String, Vec<String>)> {
    let mut taken: Vec<(String, Vec<String>)> = storage
        .logouts
        .claim(&acme(), 10)
        .await
        .expect("claimed")
        .into_iter()
        .map(|delivery| {
            assert_eq!(delivery.user, user());
            assert_eq!(delivery.attempts, 1);
            let mut clients: Vec<String> = delivery
                .clients
                .iter()
                .map(|id| id.as_str().to_owned())
                .collect();
            clients.sort();
            (delivery.sid, clients)
        })
        .collect();
    taken.sort();
    taken
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_way_a_session_ends_leaves_one_delivery_naming_its_clients() {
    let storage = fresh(&acme(), 2).await;
    let by_cookie = opened(&storage, "cookie-1", &["portal", "kiosk"]).await;
    let by_sid = opened(&storage, "cookie-2", &["portal"]).await;
    let everywhere = opened(&storage, "cookie-3", &["kiosk"]).await;
    let silent = opened(&storage, "cookie-4", &[]).await;
    assert_eq!(
        storage
            .sessions
            .end(&acme(), &SessionSecret::from_secret("cookie-1"))
            .await,
        Ok(true)
    );
    assert_eq!(
        storage.sessions.end_sid(&acme(), &user(), &by_sid).await,
        Ok(true)
    );
    assert_eq!(
        storage
            .sessions
            .end_all(&acme(), &user(), None, Timestamp::from_unix_secs(START))
            .await,
        Ok(2),
        "the last two"
    );
    let mut expected = vec![
        (by_cookie, vec!["kiosk".to_owned(), "portal".to_owned()]),
        (by_sid, vec!["portal".to_owned()]),
        (everywhere, vec!["kiosk".to_owned()]),
    ];
    expected.sort();
    assert_eq!(claimed(&storage).await, expected);
    assert!(
        !expected.iter().any(|(sid, _)| *sid == silent),
        "a session that signed nobody in owes nothing"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_claimed_delivery_is_held_and_finished_once() {
    let storage = fresh(&acme(), 2).await;
    opened(&storage, "cookie-1", &["portal"]).await;
    storage
        .sessions
        .end(&acme(), &SessionSecret::from_secret("cookie-1"))
        .await
        .expect("ended");
    let taken = storage.logouts.claim(&acme(), 10).await.expect("claimed");
    assert_eq!(taken.len(), 1);
    assert!(
        storage
            .logouts
            .claim(&acme(), 10)
            .await
            .expect("claimed")
            .is_empty(),
        "held by the first claim"
    );
    assert_eq!(
        storage.logouts.finish(&acme(), &taken[0].id).await,
        Ok(true)
    );
    assert_eq!(
        storage.logouts.finish(&acme(), &taken[0].id).await,
        Ok(false)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_retried_delivery_keeps_only_the_clients_still_untold_and_waits_its_delay() {
    let storage = fresh(&acme(), 2).await;
    opened(&storage, "cookie-1", &["portal", "kiosk"]).await;
    opened(&storage, "cookie-2", &["portal"]).await;
    for value in ["cookie-1", "cookie-2"] {
        storage
            .sessions
            .end(&acme(), &SessionSecret::from_secret(value))
            .await
            .expect("ended");
    }
    let mut taken = storage.logouts.claim(&acme(), 10).await.expect("claimed");
    taken.sort_by_key(|delivery| delivery.clients.len());
    let (later, now) = (&taken[0], &taken[1]);
    assert_eq!(
        storage
            .logouts
            .retry(&acme(), &now.id, &[client("portal")], 0)
            .await,
        Ok(())
    );
    assert_eq!(
        storage
            .logouts
            .retry(&acme(), &later.id, &later.clients, 60)
            .await,
        Ok(())
    );
    let again = storage.logouts.claim(&acme(), 10).await.expect("claimed");
    assert_eq!(again.len(), 1, "the delayed one is not due");
    assert_eq!(again[0].id, now.id);
    assert_eq!(again[0].clients, vec![client("portal")]);
    assert_eq!(again[0].attempts, 2);
}
