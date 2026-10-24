//! A sign-in in progress as the service hands it out.

use tessari_oauth_core::ceremony::Ceremony;

/// What a sign-in is for, which decides where it continues once complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// It answers the pending authorization with this interaction id.
    Authorization(String),
    /// It opens a session for the account page, and answers no authorization.
    Account,
}

/// One browser's sign-in in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signin {
    /// What it is for.
    pub purpose: Purpose,
    /// How far it has come.
    pub ceremony: Ceremony,
    /// The key the identified address's sign-in failures are counted under, once somebody is identified.
    pub account: Option<String>,
    /// The revision the next step is written over.
    pub revision: i64,
}
