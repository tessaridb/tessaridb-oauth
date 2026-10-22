//! A company's groups: named sets of its users, each carrying the roles its members are released as, with no group
//! inside another.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::{GroupEntity, MembershipEntity};
pub use model::{Group, GroupCreated, Joined, Membership, NewGroup};
pub use service::GroupService;
pub(crate) use tessaridb::TessaridbGroupRepository;
