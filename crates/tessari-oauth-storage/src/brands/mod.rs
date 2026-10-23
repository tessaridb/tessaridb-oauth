//! A company's brand on its public pages, one record in the company's own database, and its logo kept in a record of
//! its own so reading the brand never carries the image.

mod entity;
mod repository;
mod service;
mod tessaridb;

pub use entity::{BrandEntity, LogoEntity};
pub use service::{Brand, BrandService};
pub(crate) use tessaridb::TessaridbBrandRepository;
