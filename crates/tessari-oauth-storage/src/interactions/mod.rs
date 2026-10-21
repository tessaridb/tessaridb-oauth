//! Pending authorizations: a validated `/authorize` request kept while its user signs in, for at most ten minutes.

mod entity;
mod repository;
mod service;
mod tessaridb;

pub use entity::InteractionEntity;
pub use service::InteractionService;
pub(crate) use tessaridb::TessaridbInteractionRepository;
