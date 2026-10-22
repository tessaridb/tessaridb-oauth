//! The protocol core: request validation and state transitions over typed values, with the clock and the
//! source of randomness injected. It performs no I/O, so every refusal it encodes is testable without a server.

pub mod access_token;
pub mod assertion;
pub mod authentication;
pub mod authorize;
pub mod ceremony;
pub mod client_credentials;
pub mod clients;
pub mod codes;
pub mod consents;
pub mod discovery;
pub mod dpop;
mod error;
pub mod factor_change;
pub mod id_token;
pub mod jose;
pub mod keys;
pub mod logout;
mod params;
pub mod password;
pub mod refresh;
mod refusal;
pub mod signin;
pub mod subject;
pub mod token;
pub mod totp;
pub mod two_factor;
pub mod userinfo;
pub mod webauthn;

pub use error::{Error, Result};
pub use params::Params;
pub use refusal::Reason;

#[cfg(test)]
mod fixtures;
