//! One mail as the server sends it: plain UTF-8 text to one recipient, from the configured sender, every header
//! built by the mail library from typed values; a line break in the subject is encoded by it, never sent raw.

use lettre::Message;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use tessari_oauth_types::EmailAddress;

use crate::{Error, Result};

/// The configured sender; the display name, when given, is replaced per company by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sender {
    /// The display name.
    pub name: Option<String>,
    /// The address.
    pub address: String,
}

/// A mail to one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingMail {
    /// The recipient.
    pub to: EmailAddress,
    /// The subject, one line.
    pub subject: String,
    /// The body, plain text.
    pub text: String,
}

fn unbuildable(reason: &str) -> Error {
    Error::Mail {
        reason: format!("the mail could not be built: {reason}"),
    }
}

impl OutgoingMail {
    /// The message as it is submitted, from `sender`.
    ///
    /// # Errors
    ///
    /// [`Error::Mail`] when an address does not form a mailbox.
    pub fn message(&self, sender: &Sender) -> Result<Message> {
        let from = Mailbox::new(
            sender.name.clone(),
            sender
                .address
                .parse()
                .map_err(|_| unbuildable("the sender's address"))?,
        );
        let to = Mailbox::new(
            None,
            self.to
                .as_str()
                .parse()
                .map_err(|_| unbuildable("the recipient's address"))?,
        );
        Message::builder()
            .from(from)
            .to(to)
            .subject(self.subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .body(self.text.clone())
            .map_err(|_| unbuildable("the message"))
    }
}

#[cfg(test)]
#[path = "message_tests.rs"]
mod tests;
