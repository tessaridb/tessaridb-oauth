//! What the console reads and is answered about a company's mail wording.

use tessari_oauth_core::mail_template::{MailKind, Template, TemplateRefused};

/// The wording a company sends one kind with, and whether it is the company's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wording {
    /// The kind.
    pub kind: MailKind,
    /// The wording in force.
    pub template: Template,
    /// Whether it is the company's own rather than the default.
    pub own: bool,
    /// The revision a change names: the company's stored row's, 0 when it keeps none.
    pub revision: u64,
}

/// What setting a company's own wording did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Set {
    /// Kept, at this revision.
    Made(u64),
    /// Not kept: the wording moved since the revision named was read.
    Moved,
    /// Not kept: the wording breaks a rule of its kind.
    Refused(TemplateRefused),
}

/// What resetting a kind to the default did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reset {
    /// The company's own wording is gone and the default is sent again.
    Made,
    /// Nothing removed: the wording moved since the revision named was read.
    Moved,
    /// Nothing removed: the company keeps no wording of its own for the kind.
    None,
}
