//! The store over TLS: work runs when the node's chain leads to the configured authority, and nothing runs when
//! it does not.

use tessari_oauth_infrastructure::Error as StoreError;
use tessari_oauth_storage::Error;
use tessari_oauth_storage::codes::Consumed;
use tessari_oauth_types::{AuthorizationCode, TenantId, Timestamp};

use crate::codes::issued;
use crate::{fresh_on, tls_node};

fn tenant() -> TenantId {
    TenantId::parse("acme-eu").expect("a tenant id")
}

#[tokio::test]
#[ignore = "needs a TessariDB node serving TLS: set TESSARIDB_OAUTH_TEST_TLS_STORE and _TLS_AUTHORITY"]
async fn a_code_is_issued_and_spent_over_tls_to_the_node_the_authority_vouches_for() {
    let storage = fresh_on(tls_node("TESSARIDB_OAUTH_TEST_TLS_AUTHORITY"), 2);
    storage
        .tenants
        .provision(&tenant())
        .await
        .expect("provisioned over TLS");
    let code = AuthorizationCode::from_secret("tls-code-secret");
    storage.codes.issue(&code, &issued()).await.expect("issued");
    let spent = storage
        .codes
        .consume(&tenant(), &code, Timestamp::from_unix_secs(1_800_000_000))
        .await
        .expect("answered");
    assert_eq!(spent, Consumed::Fresh(issued()));
}

#[tokio::test]
#[ignore = "needs a TessariDB node serving TLS: set TESSARIDB_OAUTH_TEST_TLS_STORE and _TLS_OTHER_AUTHORITY"]
async fn a_node_the_authority_does_not_vouch_for_is_not_reached() {
    let storage = fresh_on(tls_node("TESSARIDB_OAUTH_TEST_TLS_OTHER_AUTHORITY"), 1);
    let refused = storage
        .tenants
        .provision(&tenant())
        .await
        .expect_err("an untrusted chain is refused");
    let chain_refused = matches!(
        &refused,
        Error::Store(StoreError::Unavailable { message }) if message.contains("UnknownIssuer")
    );
    assert!(
        chain_refused,
        "refused for its certificate chain: {refused:?}"
    );
}
