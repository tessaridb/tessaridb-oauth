//! Adapters with no protocol logic: the TessariDB connection, key custody, and outbound HTTP guarded
//! against server-side request forgery.

pub mod custody;
mod error;
pub mod tessaridb;

pub use error::{Error, Result};
