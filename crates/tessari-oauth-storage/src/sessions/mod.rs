//! Sessions at this issuer: who signed in, how and when, kept under the digest of the browser's session cookie
//! value until the session is idle too long, too old, or ended.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::SessionEntity;
pub use model::Session;
pub use service::SessionService;
pub(crate) use tessaridb::TessaridbSessionRepository;
