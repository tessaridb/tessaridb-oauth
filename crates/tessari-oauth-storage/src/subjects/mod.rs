//! A tenant's pairwise subjects: the salt every client's view of a user is derived under, made once and kept sealed.

mod entity;
mod repository;
mod service;
mod tessaridb;

pub use entity::SecretEntity;
pub use service::SubjectService;
pub(crate) use tessaridb::TessaridbSecretRepository;
