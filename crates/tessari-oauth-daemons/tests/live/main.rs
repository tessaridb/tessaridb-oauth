//! Daemons end to end against a real TessariDB node.
//!
//! Needs `TESSARIDB_OAUTH_TEST_STORE`, `TESSARIDB_OAUTH_TEST_USER` and `TESSARIDB_OAUTH_TEST_PASSWORD`, as the
//! storage live suite does; without them every test is `ignored`, and
//! `cargo test -p tessari-oauth-daemons --test live -- --ignored` runs them. Each test works in a region namespace
//! of its own.

#![cfg(test)]

mod directory_refresh;
mod email_change_apply;
mod key_rotation;
mod logout_delivery;
mod mail_delivery;

use std::sync::Arc;

use tessari_oauth_infrastructure::custody::Kek;
use tessari_oauth_storage::Storage;
use tessari_oauth_test_support::{fresh_storage, plain_node};

/// Storage on the plain test node for a region nobody else uses.
pub(crate) fn storage() -> Storage {
    let node = plain_node().expect("the plain node is named");
    fresh_storage(node, 4).expect("a configuration the pool accepts")
}

/// A key-encryption key read from a fresh owner-only file, which is removed once read.
pub(crate) fn fresh_kek() -> Arc<Kek> {
    Arc::new(tessari_oauth_test_support::fresh_kek().expect("a test key-encryption key"))
}
