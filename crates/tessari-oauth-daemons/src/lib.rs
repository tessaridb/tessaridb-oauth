//! Background work with graceful shutdown: expiry sweeps, signing-key rotation, back-channel logout
//! delivery and audit shipping.

mod daemon;
mod directory_refresh;
mod error;
mod key_rotation;
mod logout_delivery;
mod runner;

pub use daemon::{Daemon, DaemonFuture, DaemonReport};
pub use directory_refresh::DirectoryRefresh;
pub use error::{Error, Result};
pub use key_rotation::KeyRotation;
pub use logout_delivery::{LogoutDelivery, LogoutSender};
pub use runner::run;
