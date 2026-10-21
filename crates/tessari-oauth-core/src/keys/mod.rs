//! Signing keys as the protocol core sees them: records and the rule that rotates them.

mod rotation;

pub use rotation::{KeyPlan, KeyRecord, plan};
