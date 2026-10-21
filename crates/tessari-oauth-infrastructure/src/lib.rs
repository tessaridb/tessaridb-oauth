//! Adapters with no protocol logic: the TessariDB connection, key custody, and outbound HTTP guarded
//! against server-side request forgery.

mod error;

pub use error::{Error, Result};
