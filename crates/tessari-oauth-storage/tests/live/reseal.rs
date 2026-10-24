//! Moving every sealed value of a tenant from one key-encryption key to another: signing keys, the pairwise salt,
//! enrolled and pending authenticator secrets and queued mail all open under the new key afterwards, a second run
//! writes nothing, and a value that opens under neither key is counted and left as it was.

use tessari_oauth_core::subject::SubjectSector;
use tessari_oauth_storage::outbox::NewMail;
use tessari_oauth_storage::sealed::Resealed;
use tessari_oauth_test_support::{fresh_kek, kek_of};
use tessari_oauth_types::{Algorithm, ClientId, TenantId, Timestamp, UserId};

use crate::fresh;

const NOW: u64 = 1_800_000_000;
const SECRET: &[u8] = b"twenty byte secret!!";
const PENDING: &[u8] = b"a secret being added";

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn now() -> Timestamp {
    Timestamp::from_unix_secs(NOW)
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn every_sealed_value_opens_under_the_new_key_and_a_second_run_writes_nothing() {
    let storage = fresh(&acme(), 2).await;
    let (old, new) = (
        fresh_kek().expect("the old key"),
        kek_of(9).expect("a key-encryption key"),
    );
    let (user, client) = (
        UserId::parse("user-1").expect("a user"),
        ClientId::parse("app").expect("a client"),
    );
    let kid = storage
        .keys
        .generate(&acme(), &old, Algorithm::Es256, now())
        .await
        .expect("a signing key");
    let subject = storage
        .subjects
        .pairwise(
            &acme(),
            &old,
            &SubjectSector::Client(client.clone()),
            &user,
            now(),
        )
        .await
        .expect("a pairwise subject");
    storage
        .factors
        .enroll_totp(&acme(), &old, &user, SECRET, now())
        .await
        .expect("enrolled");
    storage
        .factors
        .begin_totp(&acme(), &old, &user, "session-1", PENDING, now())
        .await
        .expect("an enrolment begun");
    let mail = NewMail {
        to: None,
        subject: "Your sign-in changed".to_owned(),
        text: "a notice".to_owned(),
    };
    storage
        .outbox
        .enqueue(&acme(), &old, &mail)
        .await
        .expect("queued");

    let first = storage
        .sealed
        .reseal(&acme(), &old, &new)
        .await
        .expect("resealed");
    assert_eq!(
        first,
        Resealed {
            resealed: 5,
            already: 0,
            unopened: 0
        }
    );
    let again = storage
        .sealed
        .reseal(&acme(), &old, &new)
        .await
        .expect("rerun");
    assert_eq!(
        again,
        Resealed {
            resealed: 0,
            already: 5,
            unopened: 0
        },
        "a second run finds everything done and writes nothing"
    );

    let signer = storage
        .keys
        .signer(&acme(), &new, now())
        .await
        .expect("the key opens under the new KEK");
    assert_eq!(signer.kid(), &kid, "the same key signs");
    assert!(
        storage.keys.signer(&acme(), &old, now()).await.is_err(),
        "and no longer opens under the old one"
    );
    assert_eq!(
        storage
            .subjects
            .pairwise(
                &acme(),
                &new,
                &SubjectSector::Client(client.clone()),
                &user,
                now()
            )
            .await
            .expect("the salt opens under the new KEK"),
        subject,
        "the same salt, so the same subject"
    );
    let factor = storage
        .factors
        .totp(&acme(), &new, &user)
        .await
        .expect("the factor opens")
        .expect("still enrolled");
    assert_eq!(factor.secret.as_slice(), SECRET);
    let pending = storage
        .factors
        .take_pending_totp(&acme(), &new, &user, "session-1")
        .await
        .expect("the pending secret opens")
        .expect("still pending");
    assert_eq!(pending.as_slice(), PENDING);
    let claimed = storage
        .outbox
        .claim(&acme(), &new, 5)
        .await
        .expect("the mail opens under the new KEK");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].subject, mail.subject);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_value_under_neither_key_is_counted_and_left_as_it_was() {
    let storage = fresh(&acme(), 2).await;
    let (stranger, old, new) = (
        kek_of(3).expect("a key-encryption key"),
        kek_of(4).expect("a key-encryption key"),
        kek_of(5).expect("a key-encryption key"),
    );
    let user = UserId::parse("user-2").expect("a user");
    storage
        .factors
        .enroll_totp(&acme(), &stranger, &user, SECRET, now())
        .await
        .expect("enrolled under a third key");
    let done = storage
        .sealed
        .reseal(&acme(), &old, &new)
        .await
        .expect("ran");
    assert_eq!(
        done,
        Resealed {
            resealed: 0,
            already: 0,
            unopened: 1
        }
    );
    let kept = storage
        .factors
        .totp(&acme(), &stranger, &user)
        .await
        .expect("still opens under the key it was sealed with")
        .expect("still enrolled");
    assert_eq!(kept.secret.as_slice(), SECRET, "left as it was");
}
