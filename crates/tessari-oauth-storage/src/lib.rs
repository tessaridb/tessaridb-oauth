//! Persistence on TessariDB, organised by domain; every domain exposes services, never its repository.

mod answers;
pub mod codes;
pub mod consents;
mod error;
pub mod refresh;
pub mod replay;
mod retry;
mod storage;
mod tenancy;
pub mod tenants;

pub use error::{Error, Result};
pub use storage::Storage;
pub use tenancy::Tenancy;
