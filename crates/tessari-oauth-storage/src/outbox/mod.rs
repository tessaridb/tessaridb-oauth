//! The mail a company's sign-in owes: one queued record per mail, its recipient and text sealed under the
//! key-encryption key, sent later by a worker so no relay timing reaches the request that asked for it.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::MailEntity;
pub use model::{NewMail, QueuedMail};
pub use service::OutboxService;
pub(crate) use service::binding as mail_binding;
pub(crate) use tessaridb::TessaridbOutboxRepository;
