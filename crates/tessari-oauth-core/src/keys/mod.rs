//! Signing keys as the protocol core sees them: records and the rule that rotates them.

mod key_set;
mod rotation;

pub use key_set::{KeySetError, key_set};
pub use rotation::{KeyPlan, KeyRecord, plan};
