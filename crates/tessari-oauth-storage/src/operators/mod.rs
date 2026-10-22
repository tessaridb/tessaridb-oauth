//! Operator roles: which users of a company may administer it, for which tasks, until when, and on whose word.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::OperatorGrantEntity;
pub use model::{Granted, OperatorGrant, OperatorRole};
pub use service::OperatorService;
pub(crate) use tessaridb::TessaridbOperatorRepository;
