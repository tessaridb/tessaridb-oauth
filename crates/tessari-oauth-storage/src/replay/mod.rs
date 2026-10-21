//! Replay records: each client assertion and DPoP proof spent once per tenant, remembered until it has expired.

mod repository;
mod service;
mod tessaridb;

pub use service::{ReplayService, Spent};
pub(crate) use tessaridb::TessaridbReplayRepository;
