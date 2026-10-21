//! The live test node and fresh regions on it. Each fixture answers why it could not be built, and the test that
//! called it decides to fail.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tessari_oauth_infrastructure::tessaridb::{Database, StoreConfig};
use tessari_oauth_storage::{Storage, Tenancy};

/// Names handed out in this process, so two tests never share one; an independent counter.
static TURNS: AtomicU32 = AtomicU32::new(0);

/// The value of the environment variable `key`, which the live suite cannot run without.
///
/// # Errors
///
/// When `key` is unset — a live test is `ignored` unless its node is configured.
pub fn need(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("{key} is required for the live suite"))
}

/// A name starting with `prefix` that no other call in this process returns, and that a later process is unlikely to
/// repeat (process id and clock nanoseconds).
#[must_use]
pub fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.subsec_nanos())
        .unwrap_or_default();
    let turn = TURNS.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}{}x{nanos}x{turn}", std::process::id())
}

/// The plain test node, signed in as the test user.
///
/// # Errors
///
/// When the node's variables are unset.
pub fn plain_node() -> Result<StoreConfig, String> {
    Ok(StoreConfig {
        address: need("TESSARIDB_OAUTH_TEST_STORE")?,
        user: need("TESSARIDB_OAUTH_TEST_USER")?,
        password: need("TESSARIDB_OAUTH_TEST_PASSWORD")?,
        authority: None,
    })
}

/// Storage on the node `config` names, over a pool of `connections`, for a region nobody else uses; nothing
/// provisioned yet.
///
/// # Errors
///
/// When the pool refuses the configuration.
pub fn fresh_storage(config: StoreConfig, connections: usize) -> Result<Storage, String> {
    let database = Database::new(config, connections).map_err(|error| error.to_string())?;
    let tenancy = Tenancy::for_region(&unique("live")).map_err(|error| error.to_string())?;
    Ok(Storage::new(&database, &tenancy))
}
