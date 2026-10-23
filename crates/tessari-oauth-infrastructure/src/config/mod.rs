//! The server's configuration, read from the environment once at start-up.

mod node;
mod operator;
mod peers;

pub use node::{AdminConfig, NodeConfig, PublicConfig, ReadLimit, StoreSettings, TlsFiles};
pub use operator::operator_target;
pub use peers::{PeerRegion, PeerSettings};

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
