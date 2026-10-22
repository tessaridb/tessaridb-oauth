//! A tenant's users: the account record, the email address it signs in with, and its password credential.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::{CredentialEntity, EmailEntity, UserEntity};
pub use model::{Registered, StoredPassword, UserAccount, UserStatus};
pub use service::UserService;
pub(crate) use tessaridb::TessaridbUserRepository;
