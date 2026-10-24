//! Sign-ins in progress: how far one browser's sign-in has come, kept under the digest of the value in that
//! browser's sign-in cookie, moved on one step at a time and finished once.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::SigninEntity;
pub use model::{Purpose, Signin};
pub use service::SigninService;
pub(crate) use tessaridb::TessaridbSigninRepository;
