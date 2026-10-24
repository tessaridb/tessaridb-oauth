//! The admin console's records: a sign-in is taken back once, by the browser that began it, carrying what it sent;
//! a session is found until it is ended, idles out after thirty minutes without a request and ends after eight hours
//! however busy it is.

use tessari_oauth_constants::{ADMIN_SESSION_ABSOLUTE_SECS, ADMIN_SESSION_IDLE_SECS};
use tessari_oauth_core::authentication::Method;
use tessari_oauth_storage::admin::Claim;
use tessari_oauth_types::{
    Actor, IdempotencyKey, SessionSecret, SigninBinding, TenantId, Timestamp, UserId,
};

use crate::fresh;

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn operator() -> UserId {
    UserId::parse("user-1").expect("a user id")
}

fn actor() -> Actor {
    Actor::Operator(operator())
}

const METHODS: [Method; 2] = [Method::Password, Method::Totp];

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_signin_is_taken_once_by_the_browser_that_began_it() {
    let storage = fresh(&acme(), 2).await;
    let browser = SigninBinding::from_secret("browser-1");
    storage
        .admin
        .begin(
            &acme(),
            &browser,
            "state-1",
            "verifier-1",
            "nonce-1",
            Timestamp::from_unix_secs(1),
        )
        .await
        .expect("begun");
    let other = storage
        .admin
        .take(&acme(), &SigninBinding::from_secret("browser-2"))
        .await
        .expect("an answer");
    assert_eq!(other, None, "another browser finds nothing");
    let taken = storage
        .admin
        .take(&acme(), &browser)
        .await
        .expect("an answer")
        .expect("the sign-in");
    assert_eq!(
        (taken.verifier.as_str(), taken.nonce.as_str()),
        ("verifier-1", "nonce-1")
    );
    assert!(taken.state_matches("state-1"));
    assert!(!taken.state_matches("state-2"), "another state is refused");
    let again = storage
        .admin
        .take(&acme(), &browser)
        .await
        .expect("an answer");
    assert_eq!(again, None, "taken once");
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_session_is_found_until_it_is_ended() {
    let storage = fresh(&acme(), 2).await;
    let secret = SessionSecret::from_secret("admin-cookie-1");
    let at = Timestamp::from_unix_secs(1_000);
    storage
        .admin
        .open(&acme(), &secret, &operator(), "sid-1", &METHODS, at)
        .await
        .expect("opened");
    let found = storage
        .admin
        .find(&acme(), &secret, Timestamp::from_unix_secs(1_001))
        .await
        .expect("an answer")
        .expect("the session");
    assert_eq!(
        (
            &found.user,
            found.sid.as_str(),
            found.methods.as_slice(),
            found.auth_time
        ),
        (&operator(), "sid-1", METHODS.as_slice(), at)
    );
    let stranger = storage
        .admin
        .find(
            &acme(),
            &SessionSecret::from_secret("admin-cookie-2"),
            Timestamp::from_unix_secs(1_001),
        )
        .await
        .expect("an answer");
    assert_eq!(stranger, None, "another cookie opens nothing");
    assert!(
        storage
            .admin
            .end(&acme(), &secret)
            .await
            .expect("an answer")
    );
    let after = storage
        .admin
        .find(&acme(), &secret, Timestamp::from_unix_secs(1_002))
        .await
        .expect("an answer");
    assert_eq!(after, None, "ended");
    assert!(
        !storage
            .admin
            .end(&acme(), &secret)
            .await
            .expect("an answer"),
        "ended once"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_session_idles_out_and_ends_at_its_absolute_limit() {
    let storage = fresh(&acme(), 2).await;
    let start: u64 = 10_000;
    let idle = SessionSecret::from_secret("admin-idle");
    let busy = SessionSecret::from_secret("admin-busy");
    for secret in [&idle, &busy] {
        storage
            .admin
            .open(
                &acme(),
                secret,
                &operator(),
                "sid-1",
                &METHODS,
                Timestamp::from_unix_secs(start),
            )
            .await
            .expect("opened");
    }
    let quiet = storage
        .admin
        .find(
            &acme(),
            &idle,
            Timestamp::from_unix_secs(start + ADMIN_SESSION_IDLE_SECS),
        )
        .await
        .expect("an answer");
    assert_eq!(quiet, None, "thirty minutes without a request");
    // A request just inside every idle window keeps it alive until the absolute limit, and not a second past it.
    let mut at = start;
    while at + ADMIN_SESSION_IDLE_SECS - 1 < start + ADMIN_SESSION_ABSOLUTE_SECS {
        at += ADMIN_SESSION_IDLE_SECS - 1;
        let found = storage
            .admin
            .find(&acme(), &busy, Timestamp::from_unix_secs(at))
            .await
            .expect("an answer");
        assert!(found.is_some(), "alive at {at}");
    }
    let ended = storage
        .admin
        .find(
            &acme(),
            &busy,
            Timestamp::from_unix_secs(start + ADMIN_SESSION_ABSOLUTE_SECS),
        )
        .await
        .expect("an answer");
    assert_eq!(ended, None, "eight hours after the sign-in");
}

fn key(raw: &str) -> IdempotencyKey {
    IdempotencyKey::parse(raw).expect("a key")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_change_is_claimed_once_and_answered_the_same_when_sent_again() {
    let storage = fresh(&acme(), 2).await;
    let at = Timestamp::from_unix_secs(1);
    let first = key("change-0123456789-a");
    let claim = |operator: Actor, key: IdempotencyKey, request: &'static str| {
        let admin = std::sync::Arc::clone(&storage.admin);
        async move {
            admin
                .claim(&acme(), &operator, &key, "user.disable", request, at)
                .await
                .expect("an answer")
        }
    };
    assert_eq!(claim(actor(), first.clone(), "body-1").await, Claim::Fresh);
    assert_eq!(
        claim(actor(), first.clone(), "body-1").await,
        Claim::InFlight,
        "a repeat while the first is being made"
    );
    storage
        .admin
        .finish(&acme(), &actor(), &first, 200, "{\"disabled\":true}")
        .await
        .expect("finished");
    assert_eq!(
        claim(actor(), first.clone(), "body-1").await,
        Claim::Answered {
            status: 200,
            answer: "{\"disabled\":true}".to_owned()
        }
    );
    assert_eq!(
        claim(actor(), first.clone(), "body-2").await,
        Claim::Reused,
        "the same key for another change"
    );
    let colleague = UserId::parse("user-2").expect("a user id");
    assert_eq!(
        claim(Actor::Operator(colleague), first.clone(), "body-1").await,
        Claim::Fresh,
        "another operator's key is their own"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_change_that_did_not_happen_releases_its_key() {
    let storage = fresh(&acme(), 2).await;
    let at = Timestamp::from_unix_secs(1);
    let failed = key("change-0123456789-b");
    let admin = &storage.admin;
    assert_eq!(
        admin
            .claim(&acme(), &actor(), &failed, "user.disable", "body-1", at)
            .await
            .expect("an answer"),
        Claim::Fresh
    );
    admin
        .release(&acme(), &actor(), &failed)
        .await
        .expect("released");
    assert_eq!(
        admin
            .claim(&acme(), &actor(), &failed, "user.disable", "body-1", at)
            .await
            .expect("an answer"),
        Claim::Fresh,
        "sent again after a failure, it is made"
    );
}
