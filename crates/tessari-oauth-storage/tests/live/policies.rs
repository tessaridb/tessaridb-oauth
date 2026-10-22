//! A company's two-factor policy: optional until set, and read back as set.

use tessari_oauth_core::two_factor::TwoFactorPolicy;
use tessari_oauth_types::TenantId;

use crate::fresh;

fn tenant(name: &str) -> TenantId {
    TenantId::parse(name).expect("a tenant id")
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn the_two_factor_policy_is_optional_until_set_and_read_back_as_set() {
    let storage = fresh(&tenant("acme"), 2).await;
    let policies = &storage.policies;
    assert_eq!(
        policies.two_factor(&tenant("acme")).await,
        Ok(TwoFactorPolicy::Optional)
    );
    for policy in [
        TwoFactorPolicy::Required,
        TwoFactorPolicy::Off,
        TwoFactorPolicy::Optional,
    ] {
        policies
            .set_two_factor(&tenant("acme"), policy)
            .await
            .expect("set");
        assert_eq!(policies.two_factor(&tenant("acme")).await, Ok(policy));
    }
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn a_policy_change_names_the_policy_it_replaces_and_loses_to_one_made_meanwhile() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 2).await;
    let policies = &storage.policies;
    assert_eq!(
        policies
            .set_two_factor_if(&acme, TwoFactorPolicy::Required, TwoFactorPolicy::Off)
            .await,
        Ok(false),
        "the policy is optional, not required"
    );
    assert_eq!(
        policies.two_factor(&acme).await,
        Ok(TwoFactorPolicy::Optional)
    );
    assert_eq!(
        policies
            .set_two_factor_if(&acme, TwoFactorPolicy::Optional, TwoFactorPolicy::Required)
            .await,
        Ok(true),
        "the first change from the default"
    );
    assert_eq!(
        policies
            .set_two_factor_if(&acme, TwoFactorPolicy::Optional, TwoFactorPolicy::Off)
            .await,
        Ok(false),
        "a second operator still believing it optional"
    );
    assert_eq!(
        policies.two_factor(&acme).await,
        Ok(TwoFactorPolicy::Required)
    );
    assert_eq!(
        policies
            .set_two_factor_if(&acme, TwoFactorPolicy::Required, TwoFactorPolicy::Off)
            .await,
        Ok(true)
    );
    assert_eq!(policies.two_factor(&acme).await, Ok(TwoFactorPolicy::Off));
}

#[tokio::test]
#[ignore = "needs a TessariDB node: set TESSARIDB_OAUTH_TEST_STORE, _USER and _PASSWORD"]
async fn of_simultaneous_policy_changes_from_one_policy_exactly_one_is_made() {
    let acme = tenant("acme");
    let storage = fresh(&acme, 8).await;
    let mut expected = TwoFactorPolicy::Optional;
    // The first round races the record's creation, every later one its replacement.
    for round in 0..4 {
        let target = if expected == TwoFactorPolicy::Required {
            TwoFactorPolicy::Off
        } else {
            TwoFactorPolicy::Required
        };
        let contenders: Vec<_> = (0..8)
            .map(|_| {
                let policies = std::sync::Arc::clone(&storage.policies);
                let acme = acme.clone();
                tokio::spawn(
                    async move { policies.set_two_factor_if(&acme, expected, target).await },
                )
            })
            .collect();
        let mut made = 0;
        for contender in contenders {
            if contender
                .await
                .expect("joined")
                .expect("an answer, never a failure")
            {
                made += 1;
            }
        }
        assert_eq!(made, 1, "round {round}: exactly one change is made");
        assert_eq!(storage.policies.two_factor(&acme).await, Ok(target));
        expected = target;
    }
}
