//! Persistence on TessariDB, organised by domain; every domain exposes services, never its repository.

pub mod admin;
mod answers;
pub mod audit;
mod bootstrap;
pub mod clients;
pub mod codes;
pub mod companies;
pub mod consents;
mod console;
pub use console::provision;
pub mod enrolments;
mod error;
pub mod factors;
pub mod interactions;
pub mod keys;
pub mod logouts;
pub mod operators;
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

pub use bootstrap::Bootstrapped;
pub use error::{Error, Result};
pub use storage::Storage;
pub use tenancy::Tenancy;
