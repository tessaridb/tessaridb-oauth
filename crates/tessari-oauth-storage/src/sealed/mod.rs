//! Every value sealed under the key-encryption key, read family by family so all of them can be sealed again under a
//! new one.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use model::Resealed;
pub use service::SealedService;
pub(crate) use tessaridb::TessaridbSealedRepository;
