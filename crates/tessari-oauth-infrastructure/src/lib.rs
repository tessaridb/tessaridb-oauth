//! Adapters with no protocol logic: the TessariDB connection, key custody, and outbound HTTP guarded
//! against server-side request forgery.

pub mod config;
pub mod custody;
mod error;
mod listener_tls;
pub mod tessaridb;

pub use error::{Error, Result};
pub use listener_tls::{ListenerTls, listener_config};
