//! Passkeys: a credential id belongs to one user and one tenant; its counter only moves forward, even when eight
//! sign-ins report it at once; a challenge is spent once, for the ceremony it was issued for, within its lifetime.

use std::sync::Arc;

use tessari_oauth_constants::WEBAUTHN_CHALLENGE_TTL_SECS;
use tessari_oauth_core::webauthn::Registered;
use tessari_oauth_storage::Storage;
use tessari_oauth_storage::passkeys::{Ceremony, Challenged, Registration};
use tessari_oauth_types::{TenantId, Timestamp, UserId};
use tokio::sync::Barrier;

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);
const CREDENTIAL: &[u8] = b"\x01credential/id+with=bytes\xff";
const CHALLENGE: &[u8] = b"a challenge of thirty-two bytes!";
const RACERS: usize = 8;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

fn user(id: &str) -> UserId {
    UserId::parse(id).expect("a user id")
}

fn registered(count: u32) -> Registered {
    Registered {
        credential_id: CREDENTIAL.to_vec(),
        public_key: b"\xa5\x01\x02\x03\x26".to_vec(),
        sign_count: count,
        user_verified: true,
        backup_eligible: true,
    }
}

async fn stored(storage: &Storage, count: u32) {
    assert_eq!(
        storage
            .passkeys
            .register(&tenant("acme"), &user("user-1"), &registered(count), NOW)
            .await,
        Ok(Registration::Created)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_credential_belongs_to_one_user_in_one_tenant() {
    let storage = fresh(&tenant("acme"), 2).await;
    storage
        .tenants
        .provision(&tenant("globex"))
        .await
        .expect("provisioned");
    stored(&storage, 3).await;
    assert_eq!(
        storage
            .passkeys
            .register(&tenant("acme"), &user("user-2"), &registered(0), NOW)
            .await,
        Ok(Registration::AlreadyRegistered),
        "another user cannot take the credential id"
    );
    let kept = storage
        .passkeys
        .passkey(&tenant("acme"), CREDENTIAL)
        .await
        .expect("read")
        .expect("a passkey");
    assert_eq!(kept.user, user("user-1"), "the first owner is kept");
    assert_eq!(kept.public_key, registered(3).public_key);
    assert_eq!(kept.sign_count, 3);
    assert!(kept.backup_eligible);
    assert_eq!(
        storage
            .passkeys
            .passkey(&tenant("globex"), CREDENTIAL)
            .await,
        Ok(None),
        "another tenant does not see it"
    );
    assert_eq!(
        storage.passkeys.passkey(&tenant("acme"), b"unknown").await,
        Ok(None)
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_counter_only_moves_forward_even_when_eight_report_it_at_once() {
    let storage = fresh(&tenant("acme"), RACERS).await;
    stored(&storage, 0).await;
    let acme = tenant("acme");
    let advance = |count| storage.passkeys.advance_count(&acme, CREDENTIAL, count);
    assert_eq!(advance(5).await, Ok(true));
    assert_eq!(advance(5).await, Ok(false), "the same counter again");
    assert_eq!(advance(3).await, Ok(false), "a counter behind");
    assert!(
        storage
            .passkeys
            .advance_count(&tenant("acme"), b"unknown", 1)
            .await
            .is_err(),
        "no credential to advance"
    );
    let gate = Arc::new(Barrier::new(RACERS));
    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..RACERS {
        let storage = storage.clone();
        let gate = Arc::clone(&gate);
        racers.spawn(async move {
            gate.wait().await;
            storage
                .passkeys
                .advance_count(&tenant("acme"), CREDENTIAL, 9)
                .await
        });
    }
    let mut moved = 0;
    while let Some(outcome) = racers.join_next().await {
        if outcome.expect("joined").expect("answered") {
            moved += 1;
        }
    }
    assert_eq!(moved, 1, "one of eight reports moves the counter");
    let kept = storage
        .passkeys
        .passkey(&tenant("acme"), CREDENTIAL)
        .await
        .expect("read")
        .expect("a passkey");
    assert_eq!(kept.sign_count, 9);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_challenge_is_spent_once_for_its_ceremony_within_its_lifetime() {
    let storage = fresh(&tenant("acme"), RACERS).await;
    let passkeys = &storage.passkeys;
    let issue = |challenge: &'static [u8], ceremony, owner: Option<&'static str>, at| async move {
        let owner = owner.map(user);
        passkeys
            .issue_challenge(&tenant("acme"), challenge, ceremony, owner.as_ref(), at)
            .await
            .expect("issued");
    };
    issue(CHALLENGE, Ceremony::Registration, Some("user-1"), NOW).await;
    assert_eq!(
        passkeys
            .spend_challenge(&tenant("acme"), CHALLENGE, Ceremony::Registration, NOW)
            .await,
        Ok(Some(Challenged {
            user: Some(user("user-1"))
        }))
    );
    assert_eq!(
        passkeys
            .spend_challenge(&tenant("acme"), CHALLENGE, Ceremony::Registration, NOW)
            .await,
        Ok(None),
        "spent once"
    );
    issue(b"for signing in", Ceremony::Assertion, None, NOW).await;
    assert_eq!(
        passkeys
            .spend_challenge(
                &tenant("acme"),
                b"for signing in",
                Ceremony::Registration,
                NOW
            )
            .await,
        Ok(None),
        "another ceremony"
    );
    assert_eq!(
        passkeys
            .spend_challenge(&tenant("acme"), b"for signing in", Ceremony::Assertion, NOW)
            .await,
        Ok(None),
        "offered to the wrong ceremony, it is gone"
    );
    issue(b"lapsing", Ceremony::Assertion, None, NOW).await;
    let lapsed =
        Timestamp::from_unix_secs(NOW.unix_secs().saturating_add(WEBAUTHN_CHALLENGE_TTL_SECS));
    assert_eq!(
        passkeys
            .spend_challenge(&tenant("acme"), b"lapsing", Ceremony::Assertion, lapsed)
            .await,
        Ok(None),
        "past its lifetime by the server's clock"
    );
    issue(b"for one of eight", Ceremony::Assertion, None, NOW).await;
    let gate = Arc::new(Barrier::new(RACERS));
    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..RACERS {
        let storage = storage.clone();
        let gate = Arc::clone(&gate);
        racers.spawn(async move {
            gate.wait().await;
            storage
                .passkeys
                .spend_challenge(
                    &tenant("acme"),
                    b"for one of eight",
                    Ceremony::Assertion,
                    NOW,
                )
                .await
        });
    }
    let mut spent = 0;
    while let Some(outcome) = racers.join_next().await {
        if outcome.expect("joined").expect("answered").is_some() {
            spent += 1;
        }
    }
    assert_eq!(spent, 1, "one of eight spends it");
}
