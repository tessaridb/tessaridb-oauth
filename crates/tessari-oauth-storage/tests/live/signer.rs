//! The signer: the tenant's current signing key as the rotation rule chooses it, opened from its sealed form, whose
//! tokens verify under the key the key set publishes — and no key at all when there is nothing it may sign with.

use tessari_oauth_core::access_token::TYPE;
use tessari_oauth_core::jose::{self, VerifyingKey};
use tessari_oauth_infrastructure::custody::{Kek, SigningKey};
use tessari_oauth_storage::Error;
use tessari_oauth_storage::keys::StoredKey;
use tessari_oauth_test_support::fresh_kek;
use tessari_oauth_types::{Algorithm, ErrorCategory, TenantId, Timestamp};

use crate::fresh;

const T0: u64 = 1_800_000_000;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

/// A fresh ES256 key sealed under `kek` for `sealed_for`, recorded as made at `created`.
fn sealed_key(kek: &Kek, sealed_for: &TenantId, created: u64) -> StoredKey {
    let (key, pkcs8) = SigningKey::generate(Algorithm::Es256).expect("a key");
    StoredKey {
        kid: key.kid().clone(),
        algorithm: Algorithm::Es256,
        sealed: kek
            .seal(sealed_for, key.kid().as_str(), &pkcs8)
            .expect("sealed"),
        public_jwk: key.public_jwk().expect("a public key"),
        created_at: Timestamp::from_unix_secs(created),
        compromised: false,
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_signer_signs_with_the_rules_key_and_its_tokens_verify_under_the_published_key() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    // The older key has been published for longer than the key set's cache lifetime; the newer one has not.
    let waited = sealed_key(&kek, &acme, T0);
    let fresh_one = sealed_key(&kek, &acme, T0 + 3_000);
    for key in [&waited, &fresh_one] {
        storage.keys.add(&acme, key).await.expect("added");
    }
    let signer = storage
        .keys
        .signer(&acme, &kek, Timestamp::from_unix_secs(T0 + 3_100))
        .await
        .expect("a signer");
    assert_eq!(signer.kid(), &waited.kid, "the waited key signs");
    let compact = signer
        .sign_compact(TYPE, br#"{"sub":"x"}"#)
        .expect("signed");
    let published =
        VerifyingKey::from_jwk(&waited.public_jwk, Algorithm::Es256).expect("a published key");
    let verified = jose::verify(&compact, Algorithm::Es256, &[published]).expect("verifies");
    assert_eq!(verified.typ.as_deref(), Some("at+jwt"));
    assert_eq!(verified.payload, br#"{"sub":"x"}"#);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn with_no_usable_key_there_is_no_signer() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    let now = Timestamp::from_unix_secs(T0);
    let none = storage.keys.signer(&acme, &kek, now).await;
    assert!(
        matches!(&none, Err(Error::NoSigningKey)),
        "no key: {none:?}"
    );
    let key = sealed_key(&kek, &acme, T0);
    storage.keys.add(&acme, &key).await.expect("added");
    storage
        .keys
        .compromise(&acme, &key.kid)
        .await
        .expect("withdrawn");
    let withdrawn = storage.keys.signer(&acme, &kek, now).await;
    assert!(
        matches!(&withdrawn, Err(Error::NoSigningKey)),
        "only a compromised key: {withdrawn:?}"
    );
    assert!(withdrawn.is_err_and(|error| error.category() == ErrorCategory::Unavailable));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_key_sealed_for_another_tenant_does_not_open() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    let key = sealed_key(&kek, &tenant("globex"), T0);
    storage.keys.add(&acme, &key).await.expect("added");
    let refused = storage
        .keys
        .signer(&acme, &kek, Timestamp::from_unix_secs(T0 + 600))
        .await;
    assert!(
        matches!(
            &refused,
            Err(Error::Store(
                tessari_oauth_infrastructure::Error::Custody { .. }
            ))
        ),
        "{refused:?}"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_generated_key_is_published_at_once_sealed_for_its_tenant_and_signs_when_it_is_the_only_one()
 {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let kek = fresh_kek().expect("a key-encryption key");
    let now = Timestamp::from_unix_secs(T0);
    let kid = storage
        .keys
        .generate(&acme, &kek, Algorithm::Es256, now)
        .await
        .expect("generated");
    let live = storage.keys.live(&acme).await.expect("read");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].kid, kid);
    assert_eq!(live[0].created_at, now);
    assert!(!live[0].compromised);
    assert!(
        !live[0].public_jwk.contains("\"d\""),
        "only the public half is published"
    );
    let signer = storage
        .keys
        .signer(&acme, &kek, now)
        .await
        .expect("a signer");
    assert_eq!(signer.kid(), &kid, "the only key signs, unwaited");
    let another = storage
        .keys
        .generate(&acme, &kek, Algorithm::Es256, now)
        .await
        .expect("generated");
    assert_ne!(another, kid, "a new key every time");
    assert!(
        kek.unseal(&tenant("globex"), kid.as_str(), &live[0].sealed)
            .is_err(),
        "sealed for acme alone"
    );
}
