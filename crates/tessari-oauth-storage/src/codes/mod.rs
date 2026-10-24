//! Authorization codes: issued once, consumed once.

mod entity;
mod repository;
mod service;
mod tessaridb;

pub use entity::CodeEntity;
pub use service::{CodeService, Consumed};
pub(crate) use tessaridb::TessaridbCodeRepository;
