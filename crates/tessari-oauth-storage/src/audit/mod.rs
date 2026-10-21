//! The audit trail: one immutable message per issuance, refusal, replay, reuse and revocation, in a topic the store
//! itself refuses to rewrite or delete from.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::AuditEntity;
pub use model::{AuditEvent, AuditKind, AuditRecord};
pub use service::AuditService;
pub(crate) use tessaridb::TessaridbAuditRepository;
