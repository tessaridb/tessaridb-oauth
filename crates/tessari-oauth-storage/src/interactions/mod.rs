//! Pending authorizations: a validated `/authorize` request kept while its user signs in, for at most ten minutes;
//! and a pushed one (RFC 9126), kept unclaimed for a minute until the browser brings its id.

mod entity;
mod repository;
mod service;
mod tessaridb;

pub use entity::InteractionEntity;
pub use service::InteractionService;
pub(crate) use tessaridb::TessaridbInteractionRepository;
