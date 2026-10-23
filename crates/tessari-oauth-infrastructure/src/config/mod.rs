//! The server's configuration, read from the environment once at start-up.

mod mail;
mod node;
mod operator;
mod peers;
mod reseal;

pub use mail::{MailCredentials, MailSecurity, MailSettings};
pub use node::{AdminConfig, NodeConfig, PublicConfig, ReadLimit, StoreSettings, TlsFiles};
pub use operator::operator_target;
pub use peers::{PeerRegion, PeerSettings};
pub use reseal::old_kek_path;

#[cfg(test)]
#[path = "node_tests.rs"]
mod tests;
