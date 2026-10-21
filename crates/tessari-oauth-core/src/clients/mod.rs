//! Clients as the protocol core sees them: a registration envelope and the directory that finds one.

mod registration;

pub use registration::{AuthMethod, ClientDirectory, ClientRegistration, GrantType};
