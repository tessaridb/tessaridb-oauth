//! The server's configuration, read from the environment once at start-up.

mod node;

pub use node::{NodeConfig, PublicConfig, ReadLimit, StoreSettings};

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
