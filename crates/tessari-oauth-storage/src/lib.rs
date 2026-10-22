//! Persistence on TessariDB, organised by domain; every domain exposes services, never its repository.

mod answers;
pub mod audit;
pub mod clients;
pub mod codes;
pub mod consents;
mod error;
pub mod factors;
pub mod interactions;
pub mod keys;
pub mod logouts;
pub mod passkeys;
pub mod policies;
pub mod refresh;
pub mod replay;
mod retry;
pub mod sessions;
pub mod signins;
mod storage;
pub mod subjects;
mod tenancy;
pub mod tenants;
pub mod throttle;
pub mod users;

pub use error::{Error, Result};
pub use storage::Storage;
pub use tenancy::Tenancy;
