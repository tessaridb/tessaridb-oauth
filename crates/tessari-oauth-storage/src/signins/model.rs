//! A sign-in in progress as the service hands it out.

use tessari_oauth_core::ceremony::Ceremony;

/// One browser's sign-in in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signin {
    /// The pending authorization it answers.
    pub interaction: String,
    /// How far it has come.
    pub ceremony: Ceremony,
    /// The key the identified address's sign-in failures are counted under, once somebody is identified.
    pub account: Option<String>,
    /// The revision the next step is written over.
    pub revision: i64,
}
