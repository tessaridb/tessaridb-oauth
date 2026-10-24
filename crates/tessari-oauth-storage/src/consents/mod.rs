//! Consents: what each user granted each client, how to check a request against it, and how to end it.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::ConsentEntity;
pub use model::{Consent, NewGrant, Revocation, Revoker};
pub use service::ConsentService;
pub(crate) use tessaridb::TessaridbConsentRepository;
