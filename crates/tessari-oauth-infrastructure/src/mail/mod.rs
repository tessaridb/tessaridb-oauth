//! Mail the server submits to the operator's relay: the message it builds and the relay it hands it to.

mod message;

pub use message::{OutgoingMail, Sender};
