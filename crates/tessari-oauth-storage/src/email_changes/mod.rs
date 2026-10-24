//! Changes of an account's sign-in address: each asked for by the signed-in user, confirmed by a link mailed to the new
//! address, cancellable from a link mailed to the old one, and held for a day before it takes effect.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::EmailChangeEntity;
pub use model::{ConfirmedChange, DueChange};
pub use service::{Addresses, EmailChangeService};
pub(crate) use tessaridb::TessaridbEmailChangeRepository;
