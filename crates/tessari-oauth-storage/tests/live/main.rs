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
mod tls;

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tessari_oauth_infrastructure::tessaridb::{Database, StoreConfig};
use tessari_oauth_storage::{Storage, Tenancy};
use tessari_oauth_types::TenantId;

/// Regions handed out in this process, so two tests never share a namespace; an independent counter.
static REGIONS: AtomicU32 = AtomicU32::new(0);

fn need(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} is required for the live suite"))
}

/// The plain test node, signed in as the test user.
pub(crate) fn plain_node() -> StoreConfig {
    StoreConfig {
        address: need("TESSARIDB_OAUTH_TEST_STORE"),
        user: need("TESSARIDB_OAUTH_TEST_USER"),
        password: need("TESSARIDB_OAUTH_TEST_PASSWORD"),
        authority: None,
    }
}

/// The TLS test node, trusted by the authority whose PEM file `authority_variable` names.
pub(crate) fn tls_node(authority_variable: &str) -> StoreConfig {
    let pem = std::fs::read(need(authority_variable)).expect("the authority file is readable");
    StoreConfig {
        address: need("TESSARIDB_OAUTH_TEST_TLS_STORE"),
        authority: Some(pem),
        ..plain_node()
    }
}

/// A region name nobody else uses.
fn fresh_region() -> Tenancy {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .subsec_nanos();
    let turn = REGIONS.fetch_add(1, Ordering::Relaxed);
    let region = format!("live{}x{nanos}x{turn}", std::process::id());
    Tenancy::for_region(&region).expect("a plain region name")
}

/// Storage on the plain node for a fresh region, over a pool of `connections`, with `tenant` provisioned in it.
pub(crate) async fn fresh(tenant: &TenantId, connections: usize) -> Storage {
    let storage = fresh_on(plain_node(), connections);
    storage
        .tenants
        .provision(tenant)
        .await
        .expect("tenant provisioned");
    storage
}

/// Storage on the node `config` names for a fresh region, nothing provisioned yet.
pub(crate) fn fresh_on(config: StoreConfig, connections: usize) -> Storage {
    let database = Database::new(config, connections).expect("a configuration the pool accepts");
    Storage::new(&database, &fresh_region())
}
