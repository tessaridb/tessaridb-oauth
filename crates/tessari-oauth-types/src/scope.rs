//! The `scope` parameter as a set of scope tokens (RFC 6749 §3.3).
//!
//! A set, because the specification gives the tokens no order and repeats carry no meaning; held sorted so two
//! requests naming the same scopes compare equal. The grammar is strict — one space between tokens, none at either
//! end, no `"` or `\` — so a value that splits differently under another parser is refused rather than guessed at.

use std::collections::BTreeSet;

use crate::{Error, Result};

/// Whether a byte is `NQCHAR`: `%x21 / %x23-5B / %x5D-7E` (RFC 6749 Appendix A.4).
const fn nqchar(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e)
}

/// A non-empty set of scope tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSet(BTreeSet<String>);

impl ScopeSet {
    /// Read a `scope` parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Invalid`] for `scope` when the value is empty, has an empty token (two spaces, a leading
    /// or trailing space), or holds a character outside `NQCHAR`.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut tokens = BTreeSet::new();
        for token in raw.split(' ') {
            if token.is_empty() || !token.bytes().all(nqchar) {
                return Err(Error::Invalid {
                    field: "scope",
                    reason: "space-separated tokens of printable ASCII other than `\"` and `\\`",
                });
            }
            tokens.insert(token.to_owned());
        }
        Ok(Self(tokens))
    }

    /// Whether every scope in this set is also in `ceiling`.
    #[must_use]
    pub fn is_within(&self, ceiling: &Self) -> bool {
        self.0.is_subset(&ceiling.0)
    }

    /// The scopes in sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

#[cfg(test)]
#[path = "scope_tests.rs"]
mod tests;
