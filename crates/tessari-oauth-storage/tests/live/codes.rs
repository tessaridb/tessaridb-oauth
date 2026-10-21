//! A code is spent once: in sequence, by an unknown digest, and under simultaneity on separate connections.

use std::sync::Arc;

use tessari_oauth_core::codes::IssuedCode;
use tessari_oauth_storage::codes::Consumed;
use tessari_oauth_types::{
    AuthorizationCode, Challenge, ClientId, ErrorCategory, ScopeSet, TenantId, Timestamp, UserId,
};
use tokio::sync::Barrier;

use crate::fresh;

/// The RFC 7636 appendix B verifier, whose S256 challenge the stored binding carries.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const NOW: u64 = 1_800_000_000;
const LATER: u64 = 1_800_000_001;
const EXPIRES: u64 = 1_800_000_060;

fn tenant() -> TenantId {
    TenantId::parse("acme-eu").expect("a tenant id")
}

pub(crate) fn issued() -> IssuedCode {
    IssuedCode {
        tenant: tenant(),
        client_id: ClientId::parse("portal").expect("a client id"),
        user: UserId::parse("user-7").expect("a user id"),
        redirect_uri: "https://portal.example.com/callback".to_owned(),
        challenge: Challenge::of(VERIFIER).expect("a challenge"),
        scopes: ScopeSet::parse("openid profile").expect("scopes"),
        expires_at: Timestamp::from_unix_secs(EXPIRES),
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn an_issued_code_is_consumed_once_with_its_bindings_and_then_reported_replayed() {
    let storage = fresh(&tenant(), 2).await;
    let spent = AuthorizationCode::from_secret("first-code-secret");
    storage
        .codes
        .issue(&spent, &issued())
        .await
        .expect("issued");

    let first = storage
        .codes
        .consume(&tenant(), &spent, Timestamp::from_unix_secs(NOW))
        .await
        .expect("answered");
    assert_eq!(
        first,
        Consumed::Fresh(issued()),
        "the first consume returns every binding as issued"
    );

    let second = storage
        .codes
        .consume(&tenant(), &spent, Timestamp::from_unix_secs(LATER))
        .await
        .expect("answered");
    assert_eq!(
        second,
        Consumed::Replayed(issued()),
        "the second consume is a replay carrying the record it found"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_code_nobody_issued_is_absent() {
    let storage = fresh(&tenant(), 1).await;
    storage
        .codes
        .issue(
            &AuthorizationCode::from_secret("issued-code-secret"),
            &issued(),
        )
        .await
        .expect("issued");

    let never = AuthorizationCode::from_secret("never-issued-secret");
    let unknown = storage
        .codes
        .consume(&tenant(), &never, Timestamp::from_unix_secs(NOW))
        .await
        .expect("answered");
    assert_eq!(unknown, Consumed::Absent);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_code_issued_twice_is_refused_the_second_time() {
    let storage = fresh(&tenant(), 1).await;
    let twice = AuthorizationCode::from_secret("twice-issued-secret");
    storage
        .codes
        .issue(&twice, &issued())
        .await
        .expect("issued");

    let refusal = storage
        .codes
        .issue(&twice, &issued())
        .await
        .expect_err("a second code at one digest is refused");
    assert_eq!(
        refusal.category(),
        ErrorCategory::Conflict,
        "refused as an existing record: {refusal:?}"
    );
}

/// Sixteen redemptions of one code, each on its own connection and released together, twenty rounds over.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_redemptions_of_one_code_leave_exactly_one_fresh() {
    const CONTENDERS: usize = 16;
    const LOSERS: usize = 15;
    const ROUNDS: usize = 20;
    let storage = fresh(&tenant(), CONTENDERS).await;
    for round in 0..ROUNDS {
        let contested = AuthorizationCode::from_secret(format!("contested-code-secret-{round}"));
        storage
            .codes
            .issue(&contested, &issued())
            .await
            .expect("issued");
        let start = Arc::new(Barrier::new(CONTENDERS));
        let mut contenders = Vec::with_capacity(CONTENDERS);
        for _ in 0..CONTENDERS {
            let (storage, contested, start) =
                (storage.clone(), contested.clone(), Arc::clone(&start));
            contenders.push(tokio::spawn(async move {
                start.wait().await;
                storage
                    .codes
                    .consume(&tenant(), &contested, Timestamp::from_unix_secs(NOW))
                    .await
            }));
        }
        let mut outcomes = Vec::with_capacity(CONTENDERS);
        for contender in contenders {
            outcomes.push(contender.await.expect("joined").expect("answered"));
        }
        let fresh = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Consumed::Fresh(_)))
            .count();
        let replayed = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Consumed::Replayed(_)))
            .count();
        assert_eq!(
            (fresh, replayed),
            (1, LOSERS),
            "round {round}: one redemption wins and every other is a replay"
        );
        assert!(
            outcomes.contains(&Consumed::Fresh(issued())),
            "round {round}: the winner carries the bindings"
        );
    }
}
