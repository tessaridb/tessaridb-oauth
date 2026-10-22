//! The admin console's own records: a sign-in on its way to the company issuer and back, and the session it opens.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::{AdminSessionEntity, PendingSigninEntity};
pub use model::{AdminSession, PendingSignin};
pub use service::AdminService;
pub(crate) use tessaridb::TessaridbAdminRepository;
