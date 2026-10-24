//! The companies a region serves: its directory. A company is a tenant with its own issuer, users, clients and keys;
//! the directory says which companies exist, what each is called and whether it is served.

mod elsewhere;
mod entity;
mod model;
mod repository;
mod served;
mod service;
mod tessaridb;

pub use elsewhere::Elsewhere;
pub use entity::CompanyEntity;
pub use model::{Company, CompanyStatus, Created};
pub use served::Served;
pub use service::CompanyService;
pub(crate) use tessaridb::TessaridbCompanyRepository;
