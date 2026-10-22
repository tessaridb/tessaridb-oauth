//! The admin console's own records: a sign-in on its way to the company issuer and back, the session it opens, and the
//! changes its operators send, each kept under its idempotency key.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::{AdminActionEntity, AdminSessionEntity, PendingSigninEntity};
pub use model::{AdminSession, Claim, PendingSignin};
pub use service::AdminService;
pub(crate) use tessaridb::TessaridbAdminRepository;
