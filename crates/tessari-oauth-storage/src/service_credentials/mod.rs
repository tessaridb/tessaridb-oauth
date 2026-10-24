//! Service credentials: programs a company registers to call its admin API without a console session, each with the
//! one Ed25519 key its assertions verify under and the operator roles it may act with.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::ServiceEntity;
pub use model::{NewService, ServiceCredential};
pub use service::{SERVICE_ROLES, ServiceCredentialService};
pub(crate) use tessaridb::TessaridbServiceRepository;
