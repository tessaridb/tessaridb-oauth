//! Fixtures shared by the live suites of several crates: the test node from the environment, and storage over a
//! region namespace no other test uses. A dev-dependency only; nothing in a shipped binary reaches it.

mod kek;
mod node;

pub use kek::{fresh_kek, fresh_passwords};
pub use node::{Error, fresh_storage, need, plain_node, unique};
