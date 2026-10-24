//! A tenant's signing keys: kept sealed, listed in the order they were made, retired or withdrawn by id.

use tessari_oauth_storage::keys::StoredKey;
use tessari_oauth_types::{Algorithm, KeyThumbprint, TenantId, Timestamp};

use crate::fresh;

const T0: u64 = 1_800_000_000;

fn tenant() -> TenantId {
    TenantId::parse("acme-eu").expect("a tenant id")
}

fn stored(letter: char, created: u64) -> StoredKey {
    StoredKey {
        kid: KeyThumbprint::parse(format!("{letter}{}", "A".repeat(42))).expect("a kid"),
        algorithm: Algorithm::Es256,
        sealed: vec![0, 1, 2, 255, u8::try_from(letter).expect("an ASCII letter")],
        public_jwk: format!(r#"{{"kty":"EC","kid":"{letter}"}}"#),
        created_at: Timestamp::from_unix_secs(created),
        compromised: false,
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn keys_come_back_sealed_and_in_the_order_they_were_made_until_retired() {
    let storage = fresh(&tenant(), 2).await;
    let (older, newer) = (stored('b', T0), stored('a', T0 + 10));
    for key in [&newer, &older] {
        storage.keys.add(&tenant(), key).await.expect("added");
    }
    assert_eq!(
        storage.keys.live(&tenant()).await.expect("listed"),
        vec![older.clone(), newer.clone()]
    );
    assert!(
        storage.keys.add(&tenant(), &older).await.is_err(),
        "a kid is never reused"
    );
    storage
        .keys
        .retire(&tenant(), &older.kid, Timestamp::from_unix_secs(T0 + 20))
        .await
        .expect("retired");
    assert_eq!(
        storage.keys.live(&tenant()).await.expect("listed"),
        vec![newer.clone()]
    );
    storage
        .keys
        .compromise(&tenant(), &newer.kid)
        .await
        .expect("withdrawn");
    let mut withdrawn = newer;
    withdrawn.compromised = true;
    assert_eq!(
        storage.keys.live(&tenant()).await.expect("listed"),
        vec![withdrawn]
    );
}
