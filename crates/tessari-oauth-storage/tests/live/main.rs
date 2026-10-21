//! Storage end to end against a real TessariDB node.
//!
//! Needs `TESSARIDB_OAUTH_TEST_STORE` (a node's wire `host:port`), `TESSARIDB_OAUTH_TEST_USER` and
//! `TESSARIDB_OAUTH_TEST_PASSWORD`; the TLS tests also `TESSARIDB_OAUTH_TEST_TLS_STORE` (a node serving TLS),
//! `TESSARIDB_OAUTH_TEST_TLS_AUTHORITY` (the PEM its certificate is signed by) and
//! `TESSARIDB_OAUTH_TEST_TLS_OTHER_AUTHORITY` (a PEM it is not). Each test works in a region namespace of its own.
//! Without them every test is `ignored` — visible in the summary — and
//! `cargo test -p tessari-oauth-storage --test live -- --ignored` runs them.

#![cfg(test)]

mod codes;
mod consents;
mod keys;
mod refresh;
mod replay;
mod throttle;
mod tls;

use tessari_oauth_infrastructure::tessaridb::StoreConfig;
use tessari_oauth_storage::Storage;
use tessari_oauth_test_support::{fresh_storage, need, plain_node};
use tessari_oauth_types::TenantId;

/// The TLS test node, trusted by the authority whose PEM file `authority_variable` names.
pub(crate) fn tls_node(authority_variable: &str) -> StoreConfig {
    let path = need(authority_variable).expect("the authority is named");
    let pem = std::fs::read(path).expect("the authority file is readable");
    StoreConfig {
        address: need("TESSARIDB_OAUTH_TEST_TLS_STORE").expect("the TLS node is named"),
        authority: Some(pem),
        ..plain_node().expect("the plain node is named")
    }
}

/// Storage on the plain node for a fresh region, over a pool of `connections`, with `tenant` provisioned in it.
pub(crate) async fn fresh(tenant: &TenantId, connections: usize) -> Storage {
    let storage = fresh_on(plain_node().expect("the plain node is named"), connections);
    storage
        .tenants
        .provision(tenant)
        .await
        .expect("tenant provisioned");
    storage
}

/// Storage on the node `config` names for a fresh region, nothing provisioned yet.
pub(crate) fn fresh_on(config: StoreConfig, connections: usize) -> Storage {
    fresh_storage(config, connections).expect("a configuration the pool accepts")
}
