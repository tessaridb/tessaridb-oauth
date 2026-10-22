//! Enrolment codes: the one-time codes that let a user an operator created set their first credential.

mod entity;
mod repository;
mod service;
mod tessaridb;

pub use entity::EnrolmentEntity;
pub use service::EnrolmentService;
pub(crate) use tessaridb::TessaridbEnrolmentRepository;
