//! A user's second factors: the shared secret of a time-based one-time code, and single-use recovery codes.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::TotpEntity;
pub use model::{Enrolled, FactorSummary, TotpFactor};
pub use service::FactorService;
pub(crate) use service::{binding as totp_binding, pending_binding as pending_totp_binding};
pub(crate) use tessaridb::TessaridbFactorRepository;
