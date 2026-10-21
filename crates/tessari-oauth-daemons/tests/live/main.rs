//! Daemons end to end against a real TessariDB node.
//!
//! Needs `TESSARIDB_OAUTH_TEST_STORE`, `TESSARIDB_OAUTH_TEST_USER` and `TESSARIDB_OAUTH_TEST_PASSWORD`, as the
//! storage live suite does; without them every test is `ignored`, and
//! `cargo test -p tessari-oauth-daemons --test live -- --ignored` runs them. Each test works in a region namespace
//! of its own.

#![cfg(test)]

mod key_rotation;

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_storage::Storage;
use tessari_oauth_test_support::{fresh_storage, plain_node, unique};

/// Storage on the plain test node for a region nobody else uses.
pub(crate) fn storage() -> Storage {
    let node = plain_node().expect("the plain node is named");
    fresh_storage(node, 4).expect("a configuration the pool accepts")
}

/// A key-encryption key read from a fresh owner-only file, which is removed once read.
pub(crate) fn fresh_kek() -> Arc<Kek> {
    let path = std::env::temp_dir().join(unique("kek"));
    let bytes: Vec<u8> = (0_u8..32).collect();
    std::fs::write(&path, bytes).expect("the key file is written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("the key file is owner-only");
    let kek = Kek::load(&path).expect("a valid key file");
    std::fs::remove_file(&path).expect("the key file is removed");
    Arc::new(kek)
}
