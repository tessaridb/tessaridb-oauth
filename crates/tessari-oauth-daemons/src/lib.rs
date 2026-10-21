//! Background work with graceful shutdown: expiry sweeps, signing-key rotation, back-channel logout
//! delivery and audit shipping.

mod error;

pub use error::{Error, Result};
