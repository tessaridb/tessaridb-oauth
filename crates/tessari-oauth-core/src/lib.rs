//! The protocol core: request validation and state transitions over typed values, with the clock and the
//! source of randomness injected. It performs no I/O, so every refusal it encodes is testable without a server.

pub mod authorize;
pub mod clients;
pub mod codes;
pub mod consents;
mod error;
mod params;
pub mod refresh;
mod refusal;
pub mod token;

pub use error::{Error, Result};
pub use params::Params;
pub use refusal::Reason;

#[cfg(test)]
mod fixtures;
