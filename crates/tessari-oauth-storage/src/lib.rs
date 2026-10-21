//! Persistence on TessariDB, organised by domain; every domain exposes services, never its repository.

mod error;

pub use error::{Error, Result};
