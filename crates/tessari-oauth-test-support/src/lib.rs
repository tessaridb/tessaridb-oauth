//! Fixtures shared by the live suites of several crates: the test node from the environment, and storage over a
//! region namespace no other test uses. A dev-dependency only; nothing in a shipped binary reaches it.

mod node;

pub use node::{fresh_storage, need, plain_node, unique};
