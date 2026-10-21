//! The HTTP surface: the public protocol and account routes, and the admin API with the embedded panel on its
//! own listener.

mod error;
mod idle_body;
mod serve;

pub use error::{Error, Result};
pub use serve::serve;
