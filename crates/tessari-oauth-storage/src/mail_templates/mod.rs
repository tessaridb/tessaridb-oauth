//! The wording of the mail the server sends: a default per kind for the whole region, seeded from the wording the
//! server ships with, and a company's own override of any kind in its database.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::TemplateEntity;
pub use model::{Reset, Set, Wording};
pub use service::MailTemplateService;
pub(crate) use tessaridb::TessaridbMailTemplateRepository;
