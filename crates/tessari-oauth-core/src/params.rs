//! Request parameters, with a repeated parameter refused rather than resolved.
//!
//! When a parameter appears twice, two components can each read a different copy — one validates the first
//! `redirect_uri`, another redirects to the second. The only safe reading is none at all (RFC 6749 §3.1).

use std::collections::BTreeMap;

/// The parameters of one request, each present at most once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params(BTreeMap<String, String>);

impl Params {
    /// Collect `pairs`, or name the first parameter that repeats.
    ///
    /// # Errors
    ///
    /// Returns the repeated parameter's name.
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut params = BTreeMap::new();
        for (name, value) in pairs {
            let name = name.into();
            if params.contains_key(&name) {
                return Err(name);
            }
            params.insert(name, value.into());
        }
        Ok(Self(params))
    }

    /// The value of `name`, when present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

#[cfg(test)]
#[path = "params_tests.rs"]
mod tests;
