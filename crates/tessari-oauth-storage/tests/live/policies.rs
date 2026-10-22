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
