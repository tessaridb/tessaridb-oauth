//! Background work with graceful shutdown: expiry sweeps, signing-key rotation, back-channel logout
//! delivery and audit shipping.

mod daemon;
mod error;
mod key_rotation;
mod runner;

pub use daemon::{Daemon, DaemonFuture, DaemonReport};
pub use error::{Error, Result};
pub use key_rotation::{Clock, KeyRotation};
pub use runner::run;
