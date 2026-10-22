//! The server's configuration, read from the environment once at start-up.

mod node;
mod operator;

pub use node::{AdminConfig, AdminTls, NodeConfig, PublicConfig, ReadLimit, StoreSettings};
pub use operator::operator_target;

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
