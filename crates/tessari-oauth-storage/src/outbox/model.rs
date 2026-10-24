//! A mail as the requesting flow queues it and as the sending worker reads it back.

use std::fmt;

use tessari_oauth_types::EmailAddress;

/// A mail to queue. A request that names no account queues one with no recipient, so it costs the store what any
/// other request costs and the worker drops it.
#[derive(Clone, PartialEq, Eq)]
pub struct NewMail {
    /// The recipient, when the request named an account.
    pub to: Option<EmailAddress>,
    /// The subject, one line.
    pub subject: String,
    /// The body, plain text; it may carry a link token.
    pub text: String,
}

/// A queued mail, opened, held by the claim that took it.
#[derive(Clone, PartialEq, Eq)]
pub struct QueuedMail {
    /// The record's id, which `retry` and `finish` name.
    pub id: String,
    /// The recipient, when there is one.
    pub to: Option<EmailAddress>,
    /// The subject.
    pub subject: String,
    /// The body.
    pub text: String,
    /// How many times it was claimed, this claim included.
    pub attempts: u32,
}

impl fmt::Debug for NewMail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewMail")
            .field("to", &self.to.is_some())
            .field("text", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for QueuedMail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueuedMail")
            .field("id", &self.id)
            .field("to", &self.to.is_some())
            .field("text", &"<redacted>")
            .field("attempts", &self.attempts)
            .finish_non_exhaustive()
    }
}
