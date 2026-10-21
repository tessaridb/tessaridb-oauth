//! The protocol core: request validation and state transitions over typed values, with the clock and the
//! source of randomness injected. It performs no I/O, so every refusal it encodes is testable without a server.

mod error;

pub use error::{Error, Result};
