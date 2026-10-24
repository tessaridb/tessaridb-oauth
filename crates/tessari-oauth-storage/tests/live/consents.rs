//! A consent is a record per user and client: it covers what was granted, prompts for the delta, widens without
//! losing what was granted before, survives simultaneous grants whole, and ends with the actor who ended it.

use std::collections::BTreeSet;
use std::sync::Arc;

use tessari_oauth_core::consents::{ConsentRequest, Coverage};
use tessari_oauth_storage::consents::{NewGrant, Revocation, Revoker};
use tessari_oauth_types::{ClientId, Resource, ScopeSet, TenantId, Timestamp, UserId};
use tokio::sync::Barrier;

use crate::fresh;

const POLICY: u32 = 1;
const NEWER_POLICY: u32 = 2;
const API: &str = "https://api.example.com/";

fn tenant() -> TenantId {
    TenantId::parse("acme-eu").expect("a tenant id")
}

fn user() -> UserId {
    UserId::parse("user-7").expect("a user id")
}

fn client(name: &str) -> ClientId {
    ClientId::parse(name).expect("a client id")
}

fn asked(scopes: &str, resources: &[&str]) -> ConsentRequest {
    ConsentRequest {
        scopes: ScopeSet::parse(scopes).expect("scopes"),
        resources: resources
            .iter()
            .map(|uri| Resource::parse(*uri).expect("a resource"))
            .collect(),
    }
}

fn grant(client_name: &str, request: ConsentRequest, policy_version: u32) -> NewGrant {
    NewGrant {
        tenant: tenant(),
        user: user(),
        client_id: client(client_name),
        request,
        policy_version,
        shown_version: "descriptions-v1".to_owned(),
        at: Timestamp::from_unix_secs(1_800_000_000),
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_grant_covers_what_it_granted_and_prompts_for_exactly_the_added_scope() {
    let storage = fresh(&tenant(), 2).await;
    let consents = &storage.consents;
    consents
        .grant(&grant("portal", asked("openid profile", &[API]), POLICY))
        .await
        .expect("granted");

    let inside = consents
        .check(
            &tenant(),
            &user(),
            &client("portal"),
            &asked("openid", &[API]),
            POLICY,
        )
        .await;
    assert_eq!(inside.expect("answered"), Coverage::Covered);

    let wider = asked("openid payments", &[API]);
    let delta = consents
        .check(&tenant(), &user(), &client("portal"), &wider, POLICY)
        .await
        .expect("answered");
    let expected = Coverage::Prompt {
        scopes: Some(ScopeSet::parse("payments").expect("scopes")),
        resources: BTreeSet::new(),
    };
    assert_eq!(delta, expected);

    let other = consents
        .check(
            &tenant(),
            &user(),
            &client("other-app"),
            &asked("openid", &[API]),
            POLICY,
        )
        .await;
    assert_eq!(
        other.expect("answered"),
        Coverage::Prompt {
            scopes: Some(ScopeSet::parse("openid").expect("s")),
            resources: asked("openid", &[API]).resources
        },
        "another client inherits nothing"
    );
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn widening_keeps_what_was_granted_and_a_newer_policy_replaces_it() {
    let storage = fresh(&tenant(), 2).await;
    let consents = &storage.consents;
    consents
        .grant(&grant("portal", asked("openid", &[API]), POLICY))
        .await
        .expect("granted");
    let widened = consents
        .grant(&grant("portal", asked("payments", &[API]), POLICY))
        .await
        .expect("widened");
    assert_eq!(
        widened.scopes,
        ScopeSet::parse("openid payments").expect("scopes"),
        "the earlier scope stays granted"
    );

    let replaced = consents
        .grant(&grant("portal", asked("profile", &[API]), NEWER_POLICY))
        .await
        .expect("replaced");
    assert_eq!(
        replaced.scopes,
        ScopeSet::parse("profile").expect("scopes"),
        "a newer policy starts the grant over"
    );
    assert_eq!(replaced.policy_version, NEWER_POLICY);
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_revoked_grant_covers_nothing_and_is_listed_with_its_actor() {
    let storage = fresh(&tenant(), 2).await;
    let consents = &storage.consents;
    let operator = Revoker::Operator(UserId::parse("op-1").expect("a user id"));
    let at = Timestamp::from_unix_secs(1_800_000_100);
    consents
        .grant(&grant("portal", asked("openid", &[API]), POLICY))
        .await
        .expect("granted");

    let ended = consents
        .revoke(&tenant(), &user(), &client("portal"), &operator, at)
        .await
        .expect("answered");
    assert!(ended, "a standing grant is ended");
    let again = consents
        .revoke(&tenant(), &user(), &client("portal"), &Revoker::User, at)
        .await
        .expect("answered");
    assert!(!again, "nothing stands to end the second time");
    let never = consents
        .revoke(
            &tenant(),
            &user(),
            &client("never-granted"),
            &Revoker::User,
            at,
        )
        .await;
    assert!(!never.expect("answered"), "nothing was ever granted");

    let check = consents
        .check(
            &tenant(),
            &user(),
            &client("portal"),
            &asked("openid", &[API]),
            POLICY,
        )
        .await;
    assert!(
        matches!(check.expect("answered"), Coverage::Prompt { .. }),
        "a revoked grant covers nothing"
    );
    let listed = consents.list(&tenant(), &user()).await.expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].revoked,
        Some(Revocation { at, by: operator }),
        "the first actor is the one recorded"
    );
}

/// Sixteen grants of sixteen different scopes to one client at once, twenty rounds over: one record, all sixteen.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn simultaneous_grants_leave_one_record_holding_every_grant() {
    const GRANTERS: usize = 16;
    const ROUNDS: usize = 20;
    let storage = fresh(&tenant(), GRANTERS).await;
    for round in 0..ROUNDS {
        let client_name = format!("app-{round}");
        let start = Arc::new(Barrier::new(GRANTERS));
        let mut granters = Vec::with_capacity(GRANTERS);
        for slot in 0..GRANTERS {
            let (storage, start) = (storage.clone(), Arc::clone(&start));
            let request = grant(
                &client_name,
                asked(&format!("scope-{slot}"), &[API]),
                POLICY,
            );
            granters.push(tokio::spawn(async move {
                start.wait().await;
                storage.consents.grant(&request).await
            }));
        }
        for granter in granters {
            granter.await.expect("joined").expect("granted");
        }
        let listed = storage
            .consents
            .list(&tenant(), &user())
            .await
            .expect("listed");
        let record: Vec<_> = listed
            .iter()
            .filter(|consent| consent.client_id == client(&client_name))
            .collect();
        assert_eq!(
            record.len(),
            1,
            "round {round}: one record per user and client"
        );
        let every: Vec<String> = (0..GRANTERS).map(|slot| format!("scope-{slot}")).collect();
        let expected = ScopeSet::parse(&every.join(" ")).expect("scopes");
        assert_eq!(
            record[0].scopes, expected,
            "round {round}: no simultaneous grant was lost"
        );
    }
}
