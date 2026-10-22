//! A user's second factors: the shared secret of a time-based one-time code, and single-use recovery codes.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::TotpEntity;
pub use model::{Enrolled, TotpFactor};
pub use service::FactorService;
pub(crate) use tessaridb::TessaridbFactorRepository;
