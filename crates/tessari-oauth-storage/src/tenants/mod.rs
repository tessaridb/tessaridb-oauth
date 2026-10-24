//! Tenants: bringing a tenant's database and its tables into existence.

mod repository;
mod service;
mod tessaridb;

pub use service::TenantService;
pub(crate) use tessaridb::TessaridbTenantRepository;
