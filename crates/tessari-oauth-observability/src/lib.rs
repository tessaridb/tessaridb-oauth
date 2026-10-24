//! Tracing set-up for the server binary; library crates depend on `tracing` alone and never install a subscriber.

mod error;
mod tracing;

pub use error::{Error, Result};
pub use tracing::init_tracing;
