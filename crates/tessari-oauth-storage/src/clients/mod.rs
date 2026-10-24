//! A tenant's client registrations: what each client may do, found by its id in its own tenant only.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::ClientEntity;
pub use model::NewClient;
pub use service::ClientService;
pub(crate) use tessaridb::TessaridbClientRepository;
