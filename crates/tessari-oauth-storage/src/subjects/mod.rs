//! A tenant's pairwise subjects: the salt every client's view of a user is derived under, made once and kept sealed,
//! and the user each derived subject stands for, so a resource of this server's own can find whom a token speaks for.

mod entity;
mod repository;
mod service;
mod tessaridb;

pub use entity::{SecretEntity, SubjectEntity};
pub use service::SubjectService;
pub(crate) use tessaridb::TessaridbSecretRepository;
