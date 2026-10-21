//! Client assertions: each `jti` spent once per client and tenant, remembered until the assertion has expired.

mod repository;
mod service;
mod tessaridb;

pub use service::{AssertionService, Spent};
pub(crate) use tessaridb::TessaridbAssertionRepository;
