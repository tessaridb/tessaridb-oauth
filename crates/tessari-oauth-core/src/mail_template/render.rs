//! Filling a template in: one pass over its pieces, so a value is never read as a placeholder.

use super::{MailKind, Piece, Placeholder, Rendered, Template, pieces};

fn fill(source: &str, values: &[(Placeholder, &str)]) -> Option<String> {
    let mut filled = String::with_capacity(source.len());
    for piece in pieces(source).ok()? {
        match piece {
            Piece::Text(text) => filled.push_str(&text),
            Piece::Slot(name) => {
                let placeholder = Placeholder::parse(name)?;
                let (_, value) = values.iter().find(|(given, _)| *given == placeholder)?;
                filled.push_str(value);
            }
        }
    }
    Some(filled)
}

/// `template` with `values` filled in; `None` when it is not well formed or names a value not given.
#[must_use]
pub fn render(template: &Template, values: &[(Placeholder, &str)]) -> Option<Rendered> {
    Some(Rendered {
        subject: fill(&template.subject, values)?,
        text: fill(&template.text, values)?,
    })
}

/// `template` rendered as `kind`, or the shipped wording when `template` does not render, so a mail always goes out
/// with a text that carries what its kind must carry.
#[must_use]
pub fn compose(
    kind: MailKind,
    template: &Template,
    values: &[(Placeholder, &str)],
) -> Option<Rendered> {
    render(template, values).or_else(|| render(&kind.built_in(), values))
}
