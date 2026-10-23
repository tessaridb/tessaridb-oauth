//! Mail templates: the kinds of mail the server sends, the placeholders each may carry, the check a company's own
//! wording must pass, and the rendering that fills a template in.
//!
//! A template is plain text. `{name}` is a placeholder from the kind's own list, `{{` and `}}` are literal braces, and
//! anything else in braces is refused. A kind that carries a link must keep it, and the old address's mail must name
//! the new one, so a company can reword a mail but cannot take out what makes it work. Rendering is one pass: a value
//! is never read as a placeholder, whatever it holds.

mod built_in;
mod render;

pub use render::{compose, render};

/// The most characters a subject may hold.
const SUBJECT_MAX_CHARS: usize = 200;

/// The most characters a text may hold.
const TEXT_MAX_CHARS: usize = 10_000;

/// A kind of mail the server sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailKind {
    /// The password-reset link.
    Reset,
    /// The link that verifies the account's address.
    Verify,
    /// The link that confirms a new sign-in address, to that address.
    EmailConfirm,
    /// The notice to a new address another account already signs in with.
    EmailTaken,
    /// The link that cancels a change of address, to the current address.
    EmailCancel,
    /// The notice to the old address that the change took effect.
    EmailAppliedOld,
    /// The notice to the new address that the change took effect.
    EmailAppliedNew,
    /// The notice to the old address that the change did not take effect.
    EmailRefused,
    /// The notice that something changed in how the account signs in.
    SigninChanged,
    /// The link that lets an account an operator opened set its first password.
    Enrolment,
}

/// A value a template may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Placeholder {
    /// The company's issuer.
    Issuer,
    /// The link the mail carries.
    Link,
    /// The address an account changes to.
    NewAddress,
    /// The sentence saying what changed.
    Change,
}

/// A mail's wording: a one-line subject and a text, either of which may name placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// The subject.
    pub subject: String,
    /// The text.
    pub text: String,
}

/// A template with its values filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The subject.
    pub subject: String,
    /// The text.
    pub text: String,
}

/// Why a template was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateRefused {
    /// The subject is empty or longer than 200 characters.
    SubjectLength,
    /// The text is empty or longer than 10 000 characters.
    TextLength,
    /// A control character: any in the subject, any but a line break in the text.
    ControlCharacter,
    /// A brace that opens or closes nothing.
    Unbalanced,
    /// A placeholder no kind has.
    Unknown(String),
    /// A placeholder this kind does not carry.
    NotAllowed(Placeholder),
    /// A placeholder this kind's text must carry.
    Missing(Placeholder),
}

impl MailKind {
    /// Every kind.
    pub const ALL: [Self; 10] = [
        Self::Reset,
        Self::Verify,
        Self::EmailConfirm,
        Self::EmailTaken,
        Self::EmailCancel,
        Self::EmailAppliedOld,
        Self::EmailAppliedNew,
        Self::EmailRefused,
        Self::SigninChanged,
        Self::Enrolment,
    ];

    /// The kind's name, as stored and as the console names it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reset => "reset",
            Self::Verify => "verify",
            Self::EmailConfirm => "email_confirm",
            Self::EmailTaken => "email_taken",
            Self::EmailCancel => "email_cancel",
            Self::EmailAppliedOld => "email_applied_old",
            Self::EmailAppliedNew => "email_applied_new",
            Self::EmailRefused => "email_refused",
            Self::SigninChanged => "signin_changed",
            Self::Enrolment => "enrolment",
        }
    }

    /// The kind `name` names, exactly.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// The placeholders the kind may carry.
    #[must_use]
    pub const fn placeholders(self) -> &'static [Placeholder] {
        use Placeholder::{Change, Issuer, Link, NewAddress};
        match self {
            Self::Reset | Self::Verify | Self::EmailConfirm | Self::Enrolment => &[Issuer, Link],
            Self::EmailCancel => &[Issuer, Link, NewAddress],
            Self::EmailAppliedOld => &[Issuer, NewAddress],
            Self::EmailTaken | Self::EmailAppliedNew | Self::EmailRefused => &[Issuer],
            Self::SigninChanged => &[Issuer, Change],
        }
    }

    /// The placeholders the kind's text must carry.
    #[must_use]
    pub const fn required(self) -> &'static [Placeholder] {
        use Placeholder::{Change, Link, NewAddress};
        match self {
            Self::Reset | Self::Verify | Self::EmailConfirm | Self::Enrolment => &[Link],
            Self::EmailCancel => &[Link, NewAddress],
            Self::EmailAppliedOld => &[NewAddress],
            Self::EmailTaken | Self::EmailAppliedNew | Self::EmailRefused => &[],
            Self::SigninChanged => &[Change],
        }
    }

    /// The wording the server ships with.
    #[must_use]
    pub fn built_in(self) -> Template {
        let (subject, text) = built_in::wording(self);
        Template {
            subject: subject.to_owned(),
            text: text.to_owned(),
        }
    }
}

impl Placeholder {
    const ALL: [Self; 4] = [Self::Issuer, Self::Link, Self::NewAddress, Self::Change];

    /// The name a template writes in braces.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::Link => "link",
            Self::NewAddress => "new_address",
            Self::Change => "change",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|placeholder| placeholder.name() == name)
    }
}

/// A piece of a parsed template.
pub(super) enum Piece<'a> {
    Text(String),
    Slot(&'a str),
}

/// Split `source` into literal text and placeholder names.
pub(super) fn pieces(source: &str) -> Result<Vec<Piece<'_>>, TemplateRefused> {
    let mut pieces = Vec::new();
    let mut literal = String::new();
    let mut rest = source;
    while let Some(at) = rest.find(['{', '}']) {
        let (before, from) = rest.split_at(at);
        literal.push_str(before);
        if let Some(after) = from.strip_prefix("{{") {
            literal.push('{');
            rest = after;
        } else if let Some(after) = from.strip_prefix("}}") {
            literal.push('}');
            rest = after;
        } else if let Some(inside) = from.strip_prefix('{') {
            let end = inside.find('}').ok_or(TemplateRefused::Unbalanced)?;
            let (name, after) = inside.split_at(end);
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                return Err(TemplateRefused::Unbalanced);
            }
            pieces.push(Piece::Text(std::mem::take(&mut literal)));
            pieces.push(Piece::Slot(name));
            rest = after.get(1..).unwrap_or_default();
        } else {
            return Err(TemplateRefused::Unbalanced);
        }
    }
    literal.push_str(rest);
    pieces.push(Piece::Text(literal));
    Ok(pieces)
}

/// The placeholders `source` names, each checked against `kind`.
fn named(kind: MailKind, source: &str) -> Result<Vec<Placeholder>, TemplateRefused> {
    let mut found = Vec::new();
    for piece in pieces(source)? {
        if let Piece::Slot(name) = piece {
            let placeholder = Placeholder::parse(name)
                .ok_or_else(|| TemplateRefused::Unknown(name.to_owned()))?;
            if !kind.placeholders().contains(&placeholder) {
                return Err(TemplateRefused::NotAllowed(placeholder));
            }
            found.push(placeholder);
        }
    }
    Ok(found)
}

/// Whether `template` may be used for `kind`.
///
/// # Errors
///
/// The first rule the template breaks.
pub fn check(kind: MailKind, template: &Template) -> Result<(), TemplateRefused> {
    let subject_chars = template.subject.chars().count();
    if subject_chars == 0 || subject_chars > SUBJECT_MAX_CHARS {
        return Err(TemplateRefused::SubjectLength);
    }
    let text_chars = template.text.chars().count();
    if text_chars == 0 || text_chars > TEXT_MAX_CHARS {
        return Err(TemplateRefused::TextLength);
    }
    if template.subject.chars().any(char::is_control)
        || template.text.chars().any(|c| c.is_control() && c != '\n')
    {
        return Err(TemplateRefused::ControlCharacter);
    }
    named(kind, &template.subject)?;
    let in_text = named(kind, &template.text)?;
    match kind
        .required()
        .iter()
        .find(|placeholder| !in_text.contains(placeholder))
    {
        Some(missing) => Err(TemplateRefused::Missing(*missing)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
