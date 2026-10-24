//! A user's passkeys: each credential's public key and signature counter, and the single-use challenges a ceremony
//! is answered against.

mod entity;
mod model;
mod repository;
mod service;
mod tessaridb;

pub use entity::{ChallengeEntity, PasskeyEntity};
pub use model::{Ceremony, Challenged, ListedPasskey, Passkey, Registration};
pub use service::PasskeyService;
pub(crate) use tessaridb::TessaridbPasskeyRepository;
