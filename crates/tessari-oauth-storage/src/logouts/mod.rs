//! The logouts a tenant still owes its clients: one record per ended session that had told clients, written by the
//! store in the same commit as the ending (OpenID Connect Back-Channel Logout 1.0).

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::DeliveryEntity;
pub use model::Delivery;
pub use service::LogoutService;
pub(crate) use tessaridb::TessaridbLogoutRepository;
