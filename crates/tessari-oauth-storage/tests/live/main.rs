//! Storage end to end against a real TessariDB node.
//!
//! Needs `TESSARIDB_OAUTH_TEST_STORE` (a node's wire `host:port`), `TESSARIDB_OAUTH_TEST_USER` and
//! `TESSARIDB_OAUTH_TEST_PASSWORD`; each test works in a region namespace of its own. Without them every test is
//! `ignored` — visible in the summary — and `cargo test -p tessari-oauth-storage --test live -- --ignored` runs them.

#![cfg(test)]

mod codes;
mod consents;

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

/// Storage for a region nobody else uses, over a pool of `connections`, with `tenant` provisioned in it.
pub(crate) async fn fresh(tenant: &TenantId, connections: usize) -> Storage {
    let config = StoreConfig {
        address: need("TESSARIDB_OAUTH_TEST_STORE"),
        user: need("TESSARIDB_OAUTH_TEST_USER"),
        password: need("TESSARIDB_OAUTH_TEST_PASSWORD"),
    };
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .subsec_nanos();
    let turn = REGIONS.fetch_add(1, Ordering::Relaxed);
    let region = format!("live{}x{nanos}x{turn}", std::process::id());
    let tenancy = Tenancy::for_region(&region).expect("a plain region name");
    let storage = Storage::new(&Database::new(config, connections), &tenancy);
    storage
        .tenants
        .provision(tenant)
        .await
        .expect("tenant provisioned");
    storage
}
