//! Key custody: tenant signing keys whose private half exists in plaintext only here, sealed at rest under a
//! key-encryption key read from a file.
//!
//! A file readable only by its owner is the floor of key custody, not its goal; a KMS or HSM replaces this module
//! behind the same calls. What it guarantees meanwhile: the store holds only sealed keys, a sealed key opens only for
//! the tenant and `kid` it was sealed for, and plaintext key material is cleared when it is dropped.

mod kek;
mod signing;
mod token_id;

pub use kek::Kek;
pub use signing::SigningKey;
pub use token_id::{random_secret, token_id};
