//! The server's configuration, read from the environment once at start-up.

mod node;
mod operator;
mod peers;

pub use node::{AdminConfig, AdminTls, NodeConfig, PublicConfig, ReadLimit, StoreSettings};
pub use operator::operator_target;
pub use peers::{PeerRegion, PeerSettings};

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
