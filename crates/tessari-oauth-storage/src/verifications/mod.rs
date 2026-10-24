//! Address-verification tokens: the one-time tokens a verification mail carries, each proving within a day that its
//! holder reads the address it was sent to, for the account it was sent for.

mod entity;
mod repository;
mod service;
mod tessaridb;

pub use entity::VerificationEntity;
pub use service::VerificationService;
pub(crate) use tessaridb::TessaridbVerificationRepository;
