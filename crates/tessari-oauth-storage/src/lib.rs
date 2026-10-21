//! Persistence on TessariDB, organised by domain; every domain exposes services, never its repository.

pub mod codes;
mod error;
mod storage;
mod tenancy;
pub mod tenants;

pub use error::{Error, Result};
pub use storage::Storage;
pub use tenancy::Tenancy;
