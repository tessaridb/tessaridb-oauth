//! Removing the authenticator app: its secret and every unspent recovery code go together, since the codes only
//! ever stood in for the app's code, and only the owner's are touched.

use tessari_oauth_infrastructure::custody::{recovery_codes, recovery_digest};
use tessari_oauth_storage::factors::{Enrolled, FactorSummary};
use tessari_oauth_test_support::fresh_kek;
use tessari_oauth_types::{TenantId, Timestamp, UserId};

use crate::fresh;

const NOW: Timestamp = Timestamp::from_unix_secs(1_800_000_000);

fn acme() -> TenantId {
    TenantId::parse("acme").expect("a tenant id")
}

fn user(id: &str) -> UserId {
    UserId::parse(id).expect("a user id")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn removing_the_app_takes_its_recovery_codes_and_only_the_owners() {
    let storage = fresh(&acme(), 2).await;
    let kek = fresh_kek().expect("a key");
    for id in ["user-1", "user-2"] {
        assert_eq!(
            storage
                .factors
                .enroll_totp(&acme(), &kek, &user(id), b"12345678901234567890", NOW)
                .await,
            Ok(Enrolled::Created)
        );
        let digests: Vec<String> = recovery_codes()
            .expect("codes")
            .iter()
            .map(|code| recovery_digest(code).expect("a digest"))
            .collect();
        storage
            .factors
            .issue_recovery_codes(&acme(), &user(id), &digests, NOW)
            .await
            .expect("issued");
    }
    let summary = |id: &'static str| {
        let storage = &storage;
        async move {
            storage
                .factors
                .summary(&acme(), &user(id))
                .await
                .expect("the store answers")
        }
    };
    let before = summary("user-2").await;
    assert_eq!(
        storage.factors.remove_totp(&acme(), &user("user-1")).await,
        Ok(true)
    );
    assert_eq!(
        summary("user-1").await,
        FactorSummary {
            totp: false,
            recovery_codes: 0
        }
    );
    assert_eq!(
        summary("user-2").await,
        before,
        "another user's are untouched"
    );
    assert!(before.totp && before.recovery_codes > 0);
    assert_eq!(
        storage.factors.remove_totp(&acme(), &user("user-1")).await,
        Ok(false),
        "nothing left to remove"
    );
}
